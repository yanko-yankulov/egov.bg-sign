# Python NexU-Compatible Signer

Minimal replacement for the old NexU app used to sign documents on eGov.bg.
It exposes the NexU-compatible local HTTP endpoints and signs through PKCS#11.

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
  "key_id": "0123456789abcdef",
  "preview_pdf_before_sign": true,
  "pdf_viewer_command": "xdg-open"
}
```

`config.json` is ignored by Git. See `config.example.json` for a template.

No environment variables are required. Do not put the PIN in `config.json`;
the service prompts for it on the console for each signing request.

The eGov signing flow uses `/rest/signDoc`. When `preview_pdf_before_sign` is
enabled, the service opens the uploaded PDF before the PIN prompt and waits for
console confirmation. If `pdf_viewer_command` is missing, the service uses
`xdg-open` on Linux, `open` on macOS, or the default file handler on Windows.

Server settings can also live in `config.json`:

```json
{
  "host": "127.0.0.1",
  "port": 9795
}
```

## Run

```sh
python3 app.py
```

Health check:

```sh
curl http://localhost:9795/nexu-info
```

Signing request shapes are documented in `PROTOCOL.md`.

The main eGov path posts the document to `/rest/signDoc`. The service previews
that PDF, asks for confirmation, asks for the PIN, then returns the signed PDF.

The older two-step NexU flow is still available for callers that prepare their
own data-to-sign. First call:

```sh
curl -X POST http://localhost:9795/rest/certificates
```

Then call `/rest/sign` with `toBeSigned.bytes` from the web application.

To inspect visible token objects and choose labels/IDs:

```sh
python3 app.py list-pkcs11
```

The startup wizard saves the chosen certificate object's `label` as
`cert_label` and its hex `id` as `key_id`. If you need to tune the selection
manually, edit those keys in `config.json`.

## Current limits

This is intentionally narrower than the Java fork:

- No XAdES, CAdES, ASiC, timestamps, LT/LTA, or visible signature placement.
- No UI for token/certificate selection.
- PIN is requested on the console for each signing request.
- PDF preview is available for `/rest/signDoc`. The lower-level `/rest/sign`
  endpoint only receives prepared bytes-to-sign, so there is no PDF to preview.
- Only localhost should be used; do not expose this service on a network.
