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

On startup, the service reads `config.json` from the current directory. If the
file is missing, the PKCS#11 module cannot be loaded, or no certificate choice
has been saved yet, it prompts on the console and writes the selected values
back to `config.json`.

Example:

```json
{
  "pkcs11_module": "/usr/lib/pkcs11/opensc-pkcs11.so",
  "cert_label": "SIGNING CERTIFICATE LABEL",
  "key_id": "0123456789abcdef"
  "preview_pdf_before_sign": true,
  "pdf_viewer_command": "xdg-open"
}
```

`config.json` is ignored by Git. See `config.example.json` for a template.

Environment variables still override `config.json` for scripting:

```sh
ESIG_PKCS11_MODULE
ESIG_PKCS11_TOKEN_LABEL
ESIG_PKCS11_CERT_LABEL
ESIG_PKCS11_KEY_LABEL
ESIG_PKCS11_KEY_ID
ESIG_PKCS11_SLOT_NO
ESIG_PKCS11_PIN
```

Do not put the PIN in `config.json`. If `ESIG_PKCS11_PIN` is unset, the service
prompts for the PIN on the console for each signing request.

For `/rest/signDoc`, `preview_pdf_before_sign` opens the uploaded PDF before
the PIN prompt and waits for console confirmation. If `pdf_viewer_command` is
missing, the service uses `xdg-open` on Linux, `open` on macOS, or the default
file handler on Windows.

Server:

```sh
export ESIG_HOST=127.0.0.1
export ESIG_PORT=9795
```

## Run

```sh
python3 app.py
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
python3 app.py list-pkcs11
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
- The stock `/rest/sign` flow cannot preview the PDF because the caller only
  sends the prepared bytes-to-sign to the local service.
- Only localhost should be used; do not expose this service on a network.
