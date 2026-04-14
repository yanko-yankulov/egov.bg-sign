from __future__ import annotations

import base64
import getpass
import io
import os
from dataclasses import dataclass
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
    def from_env(cls) -> "Pkcs11Config":
        module = os.environ.get("ESIG_PKCS11_MODULE")
        cert_label = os.environ.get("ESIG_PKCS11_CERT_LABEL")
        if not module:
            raise ValueError("ESIG_PKCS11_MODULE is required")

        slot_no_raw = os.environ.get("ESIG_PKCS11_SLOT_NO")
        slot_no = int(slot_no_raw) if slot_no_raw else None
        key_id_raw = os.environ.get("ESIG_PKCS11_KEY_ID")
        key_id = bytes.fromhex(key_id_raw.replace(":", "")) if key_id_raw else None

        return cls(
            module=module,
            cert_label=cert_label,
            token_label=os.environ.get("ESIG_PKCS11_TOKEN_LABEL"),
            key_label=os.environ.get("ESIG_PKCS11_KEY_LABEL"),
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
        payload = request.get_json(force=True)
        validate_request(payload)
        signed_pdf = sign_pdf_with_pkcs11(payload)
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
        return execution_error(str(exc))


@app.route("/rest/certificates", methods=["POST", "OPTIONS"])
def certificates() -> tuple[Response, int] | Response:
    if request.method == "OPTIONS":
        return Response(status=200)

    try:
        cert_info = get_certificate_info()
        return execution_ok(cert_info)
    except Exception as exc:
        return execution_error(str(exc))


@app.route("/rest/sign", methods=["POST", "OPTIONS"])
def sign() -> tuple[Response, int] | Response:
    if request.method == "OPTIONS":
        return Response(status=200)

    try:
        payload = request.get_json(force=True, silent=True) or {}
        signature_info = sign_to_be_signed(payload)
        return execution_ok(signature_info)
    except Exception as exc:
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

    level = payload["signatureLevel"].upper()
    if level not in {"PADES-BASELINE-B", "PADES_BASELINE_B"}:
        raise ValueError("Only PAdES baseline-B is supported")

    digest = payload["digestAlgorithm"].upper()
    if digest not in SUPPORTED_DIGESTS:
        raise ValueError(f"Unsupported digest algorithm: {payload['digestAlgorithm']}")

    file_bytes = base64.b64decode(payload["fileBase64Format"], validate=True)
    if not file_bytes.startswith(b"%PDF-"):
        raise ValueError("Only PDF input is supported")


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

    cfg = Pkcs11Config.from_env()
    pdf_bytes = base64.b64decode(payload["fileBase64Format"], validate=True)
    digest = SUPPORTED_DIGESTS[payload["digestAlgorithm"].upper()]
    field_name = os.environ.get("ESIG_PDF_FIELD_NAME", "Signature1")

    session = open_pkcs11_session(
        lib_location=cfg.module,
        slot_no=cfg.slot_no,
        token_label=cfg.token_label,
        user_pin=cfg.pin,
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
    cfg = Pkcs11Config.from_env()
    with open_token_session() as session:
        cert = get_pkcs11_object(
            session,
            object_class_name="CERTIFICATE",
            label=cfg.cert_label,
            object_id=cfg.key_id,
        )
        return bytes(cert[pkcs11_attribute("VALUE")])


def pkcs11_sign(data: bytes, digest_algorithm: str) -> bytes:
    cfg = Pkcs11Config.from_env()
    mechanism_name = PKCS11_RSA_MECHANISMS[digest_algorithm]
    with open_token_session(require_login=True) as session:
        key = get_pkcs11_object(
            session,
            object_class_name="PRIVATE_KEY",
            label=cfg.key_label,
            object_id=cfg.key_id,
        )
        return bytes(key.sign(data, mechanism=pkcs11_mechanism(mechanism_name)))


def open_token_session(require_login: bool = False):
    try:
        import pkcs11
    except ImportError as exc:
        raise RuntimeError(
            "python-pkcs11 is not installed. Install dependencies from requirements.txt."
        ) from exc

    cfg = Pkcs11Config.from_env()
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
    cfg = Pkcs11Config.from_env()
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
    if len(os.sys.argv) > 1 and os.sys.argv[1] == "list-pkcs11":
        import json

        print(json.dumps(list_pkcs11_objects(), indent=2, ensure_ascii=False))
        raise SystemExit(0)

    host = os.environ.get("ESIG_HOST", "127.0.0.1")
    port = int(os.environ.get("ESIG_PORT", "9795"))
    app.run(host=host, port=port)
