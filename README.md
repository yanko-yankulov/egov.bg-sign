# Python NexU-compatible signer

Minimal non-Java replacement for the old NexU fork.

This service preserves the browser-facing endpoints used by the demo:

- `GET /nexu-info`
- `POST /rest/certificates`
- `POST /rest/sign`
- `POST /rest/signDoc`

Initial scope:

- PDF input only.
- PAdES baseline-B style signing through pyHanko.
- Stock NexU certificate discovery and raw `toBeSigned` signing through
  PKCS#11 for callers that do document assembly server-side.
- SHA-256 by default.
- One configured PKCS#11 token/key/certificate.

## Install

Use a virtual environment. Flask is already available on this machine, but
pyHanko and its PKCS#11 extra are not installed globally.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Required:

```sh
export ESIG_PKCS11_MODULE=/usr/local/AWP/lib/libOcsPKCS11Wrapper.so
```

Optional selectors. Leave these unset if the token exposes exactly one usable
certificate/private key pair, which is how simple JSigPDF SunPKCS11 configs
usually work.

```sh
export ESIG_PKCS11_TOKEN_LABEL='token label'
export ESIG_PKCS11_CERT_LABEL='certificate label'
export ESIG_PKCS11_KEY_LABEL='private key label'
export ESIG_PKCS11_PIN='123456'
```

Alternative slot selection:

```sh
export ESIG_PKCS11_SLOT_NO=0
export ESIG_PKCS11_KEY_ID=0123456789abcdef
```

Server:

```sh
export ESIG_HOST=127.0.0.1
export ESIG_PORT=9795
```

## Run

```sh
python app.py
```

Health check:

```sh
curl http://localhost:9795/nexu-info
```

Signing request shape is documented in `PROTOCOL.md`.

For the two-step NexU flow used by eGov pages, first call:

```sh
curl -X POST http://localhost:9795/rest/certificates
```

Then call `/rest/sign` with `toBeSigned.bytes` from the web application.

To inspect visible token objects and choose labels/IDs:

```sh
./run.sh list-pkcs11
```

Use the chosen certificate object's `label` as `ESIG_PKCS11_CERT_LABEL`.
If the matching private key has the same label, set `ESIG_PKCS11_KEY_LABEL`
to that value too. If labels are empty or duplicated, use the private key
object's hex `id` as `ESIG_PKCS11_KEY_ID`.

## Current limits

This is intentionally narrower than the Java fork:

- No XAdES, CAdES, ASiC, timestamps, LT/LTA, or visible signature placement.
- No UI for token/certificate selection.
- PIN is read from environment for now.
- Only localhost should be used; do not expose this service on a network.
