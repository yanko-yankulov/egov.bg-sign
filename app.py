from __future__ import annotations

import base64
import getpass
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request


NEXU_VERSION = "1.23-SNAPSHOT"
SUPPORTED_DIGESTS = {
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA384": "sha384",
    "SHA512": "sha512",
}
PKCS11_RSA_MECHANISMS = {
    "SHA1": "SHA1_RSA_PKCS",
    "SHA256": "SHA256_RSA_PKCS",
    "SHA384": "SHA384_RSA_PKCS",
    "SHA512": "SHA512_RSA_PKCS",
}
TOKEN_ID = "configured-pkcs11-token"
CONFIG_PATH = Path("config.json")
CONFIG: dict[str, Any] = {}

app = Flask(__name__)


@dataclass(frozen=True)
class Pkcs11Config:
    module: str
    cert_label: str | None = None
    token_label: str | None = None
    key_label: str | None = None
    key_id: bytes | None = None
    slot_no: int | None = None
    pin: str | None = None

    @classmethod
    def current(cls) -> "Pkcs11Config":
        module = config_value("pkcs11_module", "ESIG_PKCS11_MODULE")
        cert_label = config_value("cert_label", "ESIG_PKCS11_CERT_LABEL")
        if not module:
            raise ValueError("pkcs11_module is required in config.json")

        slot_no_raw = config_value("slot_no", "ESIG_PKCS11_SLOT_NO")
        slot_no = int(slot_no_raw) if slot_no_raw else None
        key_id_raw = config_value("key_id", "ESIG_PKCS11_KEY_ID")
        key_id = bytes.fromhex(key_id_raw.replace(":", "")) if key_id_raw else None

        return cls(
            module=module,
            cert_label=cert_label,
            token_label=config_value("token_label", "ESIG_PKCS11_TOKEN_LABEL"),
            key_label=config_value("key_label", "ESIG_PKCS11_KEY_LABEL"),
            key_id=key_id,
            slot_no=slot_no,
            pin=os.environ.get("ESIG_PKCS11_PIN"),
        )


def execution_ok(response: dict[str, Any]) -> tuple[Response, int]:
    return jsonify(
        {
            "success": True,
            "response": response,
            "error": None,
            "errorMessage": None,
            "feedback": None,
        }
    ), 200


def execution_error(message: str, status: int = 500, code: str = "Exception") -> tuple[Response, int]:
    return jsonify(
        {
            "success": False,
            "response": None,
            "error": code,
            "errorMessage": message,
            "feedback": None,
        }
    ), status


def log(message: str) -> None:
    print(f"[nexu-python] {message}", flush=True)


def log_exception(context: str, exc: Exception) -> None:
    log(f"{context} failed: {exc}")
    traceback.print_exception(type(exc), exc, exc.__traceback__)


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as config_file:
            data = json.load(config_file)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid {CONFIG_PATH}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{CONFIG_PATH} must contain a JSON object")
    return data


def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(
        json.dumps(config, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def config_value(config_key: str, env_key: str) -> Any:
    if env_key in os.environ:
        return os.environ[env_key]
    return CONFIG.get(config_key)


def configure_interactively() -> None:
    global CONFIG

    CONFIG = load_config()
    log(f"Loaded configuration from {CONFIG_PATH}" if CONFIG else f"No {CONFIG_PATH} found")
    while not module_loads(config_value("pkcs11_module", "ESIG_PKCS11_MODULE")):
        current = config_value("pkcs11_module", "ESIG_PKCS11_MODULE")
        if current:
            print(f"Cannot load configured PKCS#11 module: {current}", file=sys.stderr)
        module = input("PKCS#11 module path: ").strip()
        if not module:
            continue
        CONFIG["pkcs11_module"] = module
        save_config(CONFIG)
        log(f"Saved PKCS#11 module to {CONFIG_PATH}")

    certs = list_pkcs11_certificates()
    log(f"Found {len(certs)} certificate(s) on token")
    if not certs:
        raise RuntimeError("No PKCS#11 certificates found")

    selected = select_certificate(certs)
    if "ESIG_PKCS11_CERT_LABEL" not in os.environ:
        CONFIG["cert_label"] = selected.get("label") or None
    if "ESIG_PKCS11_KEY_ID" not in os.environ:
        CONFIG["key_id"] = selected.get("id") or None
    CONFIG = {key: value for key, value in CONFIG.items() if value is not None}
    save_config(CONFIG)
    log(f"Using certificate label={CONFIG.get('cert_label')} key_id={CONFIG.get('key_id')}")


def module_loads(module: Any) -> bool:
    if not module:
        return False
    try:
        import pkcs11

        pkcs11.lib(str(module))
        return True
    except Exception:
        return False


def select_certificate(certs: list[dict[str, Any]]) -> dict[str, Any]:
    configured_label = config_value("cert_label", "ESIG_PKCS11_CERT_LABEL")
    configured_id = config_value("key_id", "ESIG_PKCS11_KEY_ID")
    for cert in certs:
        if configured_id and cert.get("id") == configured_id:
            return cert
        if configured_label and cert.get("label") == configured_label:
            return cert

    if len(certs) == 1:
        return certs[0]

    print("Available signing certificates:")
    for index, cert in enumerate(certs, start=1):
        label = cert.get("label") or "(no label)"
        subject = cert.get("subject") or "(unknown subject)"
        not_after = cert.get("not_after") or "unknown expiry"
        expired = " expired" if certificate_is_expired(cert) else ""
        print(f"  {index}. {label}")
        print(f"     {subject}")
        print(f"     valid until: {not_after}{expired}")

    while True:
        choice = input(f"Choose certificate [1-{len(certs)}]: ").strip()
        try:
            index = int(choice)
        except ValueError:
            continue
        if 1 <= index <= len(certs):
            return certs[index - 1]


def certificate_is_expired(cert: dict[str, Any]) -> bool:
    not_after = cert.get("not_after")
    if not not_after:
        return False
    from datetime import datetime

    expires_at = datetime.fromisoformat(not_after)
    return expires_at <= datetime.now(tz=expires_at.tzinfo)


@app.after_request
def add_cors_headers(response: Response) -> Response:
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Methods"] = "OPTIONS, GET, POST"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/nexu-info", methods=["GET", "OPTIONS"])
@app.route("/", methods=["GET", "OPTIONS"])
def nexu_info() -> tuple[Response, int] | Response:
    if request.method == "OPTIONS":
        return Response(status=200)
    return jsonify({"version": NEXU_VERSION})


@app.route("/rest/signDoc", methods=["POST", "OPTIONS"])
def sign_doc() -> tuple[Response, int] | Response:
    if request.method == "OPTIONS":
        return Response(status=200)

    try:
        log("POST /rest/signDoc received")
        payload = request.get_json(force=True)
        log(f"signDoc file={payload.get('fileName')} format={payload.get('signatureFormat')} level={payload.get('signatureLevel')}")
        validate_request(payload)
        log("signDoc request validated")
        preview_pdf_before_sign(payload)
        log("PDF preview accepted")
        signed_pdf = sign_pdf_with_pkcs11(payload)
        log(f"PDF signed, output bytes={len(signed_pdf)}")
        signed_name = signed_file_name(payload["fileName"])
        return execution_ok(
            {
                "success": True,
                "error": None,
                "errorMessage": None,
                "signedFileBase64": base64.b64encode(signed_pdf).decode("ascii"),
                "signedFileName": signed_name,
            }
        )
    except Exception as exc:
        log_exception("POST /rest/signDoc", exc)
        return execution_error(str(exc))


@app.route("/rest/certificates", methods=["POST", "OPTIONS"])
def certificates() -> tuple[Response, int] | Response:
    if request.method == "OPTIONS":
        return Response(status=200)

    try:
        log("POST /rest/certificates received")
        cert_info = get_certificate_info()
        log(f"Returning certificate keyId={cert_info.get('keyId')}")
        return execution_ok(cert_info)
    except Exception as exc:
        log_exception("POST /rest/certificates", exc)
        return execution_error(str(exc))


@app.route("/rest/sign", methods=["POST", "OPTIONS"])
def sign() -> tuple[Response, int] | Response:
    if request.method == "OPTIONS":
        return Response(status=200)

    try:
        log("POST /rest/sign received")
        payload = request.get_json(force=True, silent=True) or {}
        log(f"Signing toBeSigned digest={payload.get('digestAlgorithm') or 'SHA256'}")
        signature_info = sign_to_be_signed(payload)
        log(f"Signature produced, bytes={len(base64.b64decode(signature_info['signatureValue']))}")
        return execution_ok(signature_info)
    except Exception as exc:
        log_exception("POST /rest/sign", exc)
        return execution_error(str(exc))


@app.route("/debug/pkcs11", methods=["GET"])
def debug_pkcs11() -> tuple[Response, int]:
    if os.environ.get("ESIG_ENABLE_DEBUG_ENDPOINTS") != "1":
        return execution_error("Debug endpoints are disabled", status=404, code="NotFound")
    try:
        return execution_ok({"objects": list_pkcs11_objects()})
    except Exception as exc:
        return execution_error(str(exc))


def validate_request(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("JSON object expected")

    required = [
        "signatureFormat",
        "packagingFormat",
        "signatureLevel",
        "digestAlgorithm",
        "fileBase64Format",
        "fileName",
    ]
    for field in required:
        if not payload.get(field):
            raise ValueError(f"{field} is required")

    signature_format = payload["signatureFormat"].lower()
    if signature_format != "pades":
        raise ValueError("Only PAdES/PDF signing is supported by this implementation")

    packaging = payload["packagingFormat"].lower()
    if packaging != "enveloped":
        raise ValueError("Only enveloped PDF signatures are supported")

    level = normalize_signature_level(payload["signatureLevel"], signature_format)
    payload["signatureLevel"] = level
    if level != "PADES-BASELINE-B":
        raise ValueError("Only PAdES baseline-B is supported")

    digest = payload["digestAlgorithm"].upper()
    if digest not in SUPPORTED_DIGESTS:
        raise ValueError(f"Unsupported digest algorithm: {payload['digestAlgorithm']}")

    file_bytes = base64.b64decode(payload["fileBase64Format"], validate=True)
    if not file_bytes.startswith(b"%PDF-"):
        raise ValueError("Only PDF input is supported")


def normalize_signature_level(level: str, signature_format: str) -> str:
    normalized = level.strip().upper().replace("_", "-")
    if normalized == "BASELINE-B":
        return f"{signature_format.upper()}-BASELINE-B"
    return normalized


def preview_pdf_before_sign(payload: dict[str, Any]) -> None:
    if not config_bool("preview_pdf_before_sign", default=True):
        log("PDF preview disabled by config")
        return

    pdf_bytes = base64.b64decode(payload["fileBase64Format"], validate=True)
    preview_path = write_preview_pdf(pdf_bytes, payload["fileName"])
    log(f"Wrote PDF preview to {preview_path}")
    open_preview_file(preview_path)

    print(f"Review PDF before signing: {preview_path}")
    answer = input("Press Enter to sign, or type 'cancel' to abort: ").strip().lower()
    if answer in {"c", "cancel", "abort", "no", "n"}:
        raise ValueError("Signing cancelled before PIN entry")


def config_bool(config_key: str, default: bool) -> bool:
    value = CONFIG.get(config_key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def write_preview_pdf(pdf_bytes: bytes, original_name: str) -> Path:
    suffix = ".pdf"
    if original_name.lower().endswith(".pdf"):
        suffix = "-" + Path(original_name).name
    with tempfile.NamedTemporaryFile(
        prefix="nexu-sign-preview-",
        suffix=suffix,
        delete=False,
    ) as preview_file:
        preview_file.write(pdf_bytes)
        return Path(preview_file.name)


def open_preview_file(path: Path) -> None:
    command = CONFIG.get("pdf_viewer_command")
    try:
        if command:
            log(f"Opening PDF with configured command: {command}")
            subprocess.Popen([*shlex.split(str(command)), str(path)])
        elif sys.platform == "darwin":
            log("Opening PDF with open")
            subprocess.Popen(["open", str(path)])
        elif os.name == "nt":
            log("Opening PDF with default Windows handler")
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            log("Opening PDF with xdg-open")
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as exc:
        print(f"Could not open PDF viewer automatically: {exc}", file=sys.stderr)
        print(f"Open this file manually before continuing: {path}", file=sys.stderr)


def sign_pdf_with_pkcs11(payload: dict[str, Any]) -> bytes:
    try:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import signers
        from pyhanko.sign.fields import SigSeedSubFilter
        from pyhanko.sign.pkcs11 import PKCS11Signer, open_pkcs11_session
    except ImportError as exc:
        raise RuntimeError(
            "pyHanko with PKCS#11 support is not installed. "
            "Install dependencies from requirements.txt."
        ) from exc

    cfg = Pkcs11Config.current()
    pdf_bytes = base64.b64decode(payload["fileBase64Format"], validate=True)
    digest = SUPPORTED_DIGESTS[payload["digestAlgorithm"].upper()]
    field_name = os.environ.get("ESIG_PDF_FIELD_NAME", "Signature1")
    log(f"Preparing pyHanko signer digest={digest} field={field_name}")

    user_pin = cfg.pin
    if user_pin is None:
        log("Requesting PIN for PDF signature")
        user_pin = getpass.getpass("PIN for PKCS#11 signature: ")

    log("Opening PKCS#11 session for PDF signature")
    session = open_pkcs11_session(
        lib_location=cfg.module,
        slot_no=cfg.slot_no,
        token_label=cfg.token_label,
        user_pin=user_pin,
    )
    try:
        signer_kwargs = {
            "pkcs11_session": session,
            "cert_label": cfg.cert_label,
            "key_label": cfg.key_label,
            "key_id": cfg.key_id,
        }
        pkcs11_signer = PKCS11Signer(
            **{name: value for name, value in signer_kwargs.items() if value is not None}
        )
        metadata = signers.PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm=digest,
            subfilter=SigSeedSubFilter.PADES,
        )
        writer = IncrementalPdfFileWriter(io.BytesIO(pdf_bytes))
        output = io.BytesIO()
        log("Calling pyHanko PdfSigner.sign_pdf")
        signers.PdfSigner(metadata, signer=pkcs11_signer).sign_pdf(writer, output=output)
        return output.getvalue()
    finally:
        close = getattr(session, "close", None)
        if callable(close):
            close()


def signed_file_name(file_name: str) -> str:
    stem, dot, suffix = file_name.rpartition(".")
    if dot:
        return f"{stem}-signed.{suffix}"
    return f"{file_name}-signed.pdf"


def get_certificate_info() -> dict[str, Any]:
    log("Reading configured certificate from token")
    cert_der = read_pkcs11_certificate()
    encryption_algorithm = certificate_encryption_algorithm(cert_der)
    key_id = configured_key_id()
    return {
        "tokenId": {"id": TOKEN_ID},
        "keyId": key_id,
        "certificate": base64.b64encode(cert_der).decode("ascii"),
        "certificateChain": [],
        "encryptionAlgorithm": encryption_algorithm,
        "supportedDigests": ["SHA256", "SHA384", "SHA512", "SHA1"],
        "preferredDigest": "SHA256",
    }


def sign_to_be_signed(payload: dict[str, Any]) -> dict[str, Any]:
    data_to_sign = extract_to_be_signed(payload)
    digest_algorithm = str(payload.get("digestAlgorithm") or "SHA256").upper()
    if digest_algorithm not in PKCS11_RSA_MECHANISMS:
        raise ValueError(f"Unsupported digest algorithm: {digest_algorithm}")

    cert_der = read_pkcs11_certificate()
    signature = pkcs11_sign(data_to_sign, digest_algorithm)
    return {
        "signatureValue": base64.b64encode(signature).decode("ascii"),
        "signatureAlgorithm": f"{digest_algorithm}withRSA",
        "certificate": base64.b64encode(cert_der).decode("ascii"),
        "certificateChain": [],
    }


def extract_to_be_signed(payload: dict[str, Any]) -> bytes:
    if "toBeSigned" in payload and isinstance(payload["toBeSigned"], dict):
        encoded = payload["toBeSigned"].get("bytes")
    else:
        encoded = payload.get("dataToSign")

    if not encoded:
        raise ValueError("toBeSigned.bytes or dataToSign is required")
    return base64.b64decode(encoded, validate=True)


def read_pkcs11_certificate() -> bytes:
    cfg = Pkcs11Config.current()
    with open_token_session() as session:
        cert = get_pkcs11_object(
            session,
            object_class_name="CERTIFICATE",
            label=cfg.cert_label,
            object_id=cfg.key_id,
        )
        return bytes(cert[pkcs11_attribute("VALUE")])


def pkcs11_sign(data: bytes, digest_algorithm: str) -> bytes:
    cfg = Pkcs11Config.current()
    mechanism_name = PKCS11_RSA_MECHANISMS[digest_algorithm]
    log(f"Opening PKCS#11 session for raw signature, bytes={len(data)} mechanism={mechanism_name}")
    with open_token_session(require_login=True) as session:
        key = get_pkcs11_object(
            session,
            object_class_name="PRIVATE_KEY",
            label=cfg.key_label,
            object_id=cfg.key_id,
        )
        signature = bytes(key.sign(data, mechanism=pkcs11_mechanism(mechanism_name)))
        log(f"Raw PKCS#11 signature completed, bytes={len(signature)}")
        return signature


def open_token_session(require_login: bool = False):
    try:
        import pkcs11
    except ImportError as exc:
        raise RuntimeError(
            "python-pkcs11 is not installed. Install dependencies from requirements.txt."
        ) from exc

    cfg = Pkcs11Config.current()
    lib = pkcs11.lib(cfg.module)

    if cfg.slot_no is not None:
        slots = lib.get_slots(token_present=True)
        try:
            token = slots[cfg.slot_no].get_token()
        except IndexError as exc:
            raise ValueError(f"No PKCS#11 token at slot index {cfg.slot_no}") from exc
    elif cfg.token_label:
        token = lib.get_token(token_label=cfg.token_label)
    else:
        tokens = [slot.get_token() for slot in lib.get_slots(token_present=True)]
        if len(tokens) != 1:
            raise ValueError(f"Expected one PKCS#11 token, found {len(tokens)}")
        token = tokens[0]

    user_pin = cfg.pin
    if require_login and user_pin is None:
        user_pin = getpass.getpass("PIN for PKCS#11 signature: ")

    return token.open(user_pin=user_pin)


def get_pkcs11_object(session, object_class_name: str, label: str | None = None, object_id: bytes | None = None):
    criteria = {pkcs11_attribute("CLASS"): pkcs11_object_class(object_class_name)}
    if label:
        criteria[pkcs11_attribute("LABEL")] = label
    if object_id:
        criteria[pkcs11_attribute("ID")] = object_id

    if object_class_name in {"PRIVATE_KEY", "PUBLIC_KEY", "SECRET_KEY"}:
        try:
            return session.get_key(
                object_class=pkcs11_object_class(object_class_name),
                label=label,
                id=object_id,
            )
        except Exception:
            pass

    objects = list(session.get_objects(criteria))
    if len(objects) != 1:
        raise ValueError(f"Expected one PKCS#11 {object_class_name}, found {len(objects)}")
    return objects[0]


def pkcs11_object_class(name: str):
    import pkcs11

    return getattr(pkcs11.ObjectClass, name)


def pkcs11_attribute(name: str):
    import pkcs11

    return getattr(pkcs11.Attribute, name)


def pkcs11_mechanism(name: str):
    import pkcs11

    return getattr(pkcs11.Mechanism, name)


def configured_key_id() -> str:
    cfg = Pkcs11Config.current()
    if cfg.key_id:
        return cfg.key_id.hex()
    if cfg.key_label:
        return cfg.key_label
    if cfg.cert_label:
        return cfg.cert_label
    return TOKEN_ID


def certificate_encryption_algorithm(cert_der: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    cert = x509.load_der_x509_certificate(cert_der)
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA"
    return public_key.__class__.__name__


def list_pkcs11_objects() -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    with open_token_session() as session:
        for object_class_name in ("CERTIFICATE", "PRIVATE_KEY", "PUBLIC_KEY"):
            criteria = {pkcs11_attribute("CLASS"): pkcs11_object_class(object_class_name)}
            for obj in list(session.get_objects(criteria)):
                item = describe_pkcs11_object(obj, object_class_name)
                objects.append(item)
    return objects


def list_pkcs11_certificates() -> list[dict[str, Any]]:
    certs: list[dict[str, Any]] = []
    with open_token_session() as session:
        criteria = {pkcs11_attribute("CLASS"): pkcs11_object_class("CERTIFICATE")}
        for obj in list(session.get_objects(criteria)):
            certs.append(describe_pkcs11_object(obj, "CERTIFICATE"))
    return certs


def describe_pkcs11_object(obj, object_class_name: str) -> dict[str, Any]:
    item: dict[str, Any] = {"class": object_class_name}
    for attr_name in ("LABEL", "ID"):
        try:
            value = obj[pkcs11_attribute(attr_name)]
        except Exception:
            continue
        item[attr_name.lower()] = format_pkcs11_attr(value)

    if object_class_name == "CERTIFICATE":
        try:
            cert_der = bytes(obj[pkcs11_attribute("VALUE")])
            item.update(describe_certificate(cert_der))
        except Exception as exc:
            item["certificate_error"] = str(exc)
    return item


def format_pkcs11_attr(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, bytearray):
        return bytes(value).hex()
    return value


def describe_certificate(cert_der: bytes) -> dict[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert = x509.load_der_x509_certificate(cert_der)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha1": cert.fingerprint(hashes.SHA1()).hex(),
    }


if __name__ == "__main__":
    configure_interactively()

    if len(os.sys.argv) > 1 and os.sys.argv[1] == "list-pkcs11":
        print(json.dumps(list_pkcs11_objects(), indent=2, ensure_ascii=False))
        raise SystemExit(0)

    host = os.environ.get("ESIG_HOST", "127.0.0.1")
    port = int(os.environ.get("ESIG_PORT", "9795"))
    app.run(host=host, port=port)
