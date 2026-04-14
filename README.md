# Python NexU-Compatible Signer

Minimal replacement for the old NexU app used to sign documents on eGov.bg.
It exposes the NexU-compatible local HTTP endpoints and signs through PKCS#11.

## Install

Use Python 3.11 or newer with a virtual environment.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

System prerequisites:

- A working smart card/token stack, usually PC/SC plus the token vendor's
  middleware.
- A PKCS#11 shared library for the token. For example:
  `/usr/lib/pkcs11/opensc-pkcs11.so`.
- A PDF viewer. If `pdf_viewer_command` is not configured, Linux uses
  `xdg-open`.

On Debian/Ubuntu, the common system packages are:

```sh
sudo apt install python3-venv pcscd pcsc-tools opensc xdg-utils
```

Vendor middleware still has to be installed separately when the token does not
work with OpenSC.

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
  "host": "127.0.0.1",
  "pdf_field_name": "Signature1",
  "preview_pdf_before_sign": true,
  "pdf_viewer_command": "xdg-open",
  "port": 9795
}
```

`config.json` is ignored by Git. See `config.example.json` for a template.

When `preview_pdf_before_sign` is enabled, the service opens the uploaded PDF
before signing and waits for console confirmation. If `pdf_viewer_command` is
missing, the service uses `xdg-open` on Linux, `open` on macOS, or the default
file handler on Windows.

Server settings can also live in `config.json`:

```json
{
  "host": "127.0.0.1",
  "port": 9795
}
```

## Run

```sh
. .venv/bin/activate
python3 app.py
```

The service listens on `127.0.0.1:9795` by default, which is the port expected
by NexU-compatible eGov pages.

## Test

Use eGov.bg and open `Вход в моето пространство`.

This has been tested only with a КЕП token for authentication. A test document
is available under `Подписване на електронни документи`. The page currently
shows a green banner when the connection to the original NexU or this service
is established.

Health check:

```sh
curl http://localhost:9795/nexu-info
```

Signing request shapes are documented in `PROTOCOL.md`.

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

## License

BSD 2-Clause. See `LICENSE`.
