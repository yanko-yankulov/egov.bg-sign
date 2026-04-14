# NexU local signing protocol

This directory contains a fork of NexU `1.23-SNAPSHOT`. The browser-facing
part used by the bundled demo is intentionally small.

## Transport

The local component listens on loopback only.

- Default HTTP port: `9795`
- Default host used by the demo: `localhost`
- CORS: the fork config allows `*`
- Health endpoint: `GET /nexu-info`

`GET /nexu-info` returns:

```json
{ "version": "1.23-SNAPSHOT" }
```

The demo enables signing only when the returned version equals
`1.23-SNAPSHOT`.

## Demo document-signing endpoint

The demo calls:

```http
POST /rest/signDoc
Content-Type: application/json
```

Request body:

```json
{
  "container": "no",
  "signatureFormat": "pades",
  "packagingFormat": "enveloped",
  "signatureLevel": "PAdES-BASELINE-B",
  "digestAlgorithm": "SHA256",
  "fileBase64Format": "base64 document bytes",
  "fileName": "document.pdf"
}
```

Observed request fields:

- `container`: `no`, `asic-s`, or `asic-e`. The Java code maps only
  `ASiC_S` and `ASiC_E`; `no` leaves the DSS container unset.
- `signatureFormat`: `pades`, `xades`, `cades`, or `jades`. JAdES is present
  in UI/API code but effectively not implemented in the fork.
- `packagingFormat`: `enveloped`, `enveloping`, `detached`, or
  `internally_detached`.
- `signatureLevel`: DSS level such as `PAdES-BASELINE-B`,
  `XAdES-BASELINE-B`, `CAdES-BASELINE-B`.
- `digestAlgorithm`: `SHA1`, `SHA256`, `SHA384`, or `SHA512`.
- `fileBase64Format`: base64-encoded uploaded document.
- `fileName`: original file name.

Successful response is wrapped in `Execution<SignDocResponse>`:

```json
{
  "success": true,
  "response": {
    "success": true,
    "signedFileBase64": "base64 signed document bytes",
    "signedFileName": "signed-file-name"
  },
  "error": null,
  "errorMessage": null,
  "feedback": null
}
```

On error the HTTP status may be `500`, and the response keeps the same
`Execution` shape with `success: false`.

## Internal endpoints

`RestHttpPlugin` also exposes the stock NexU API through `/rest/*`:

- `POST /rest/certificates`
- `POST /rest/sign`
- `POST /rest/identityInfo`
- `POST /rest/authenticate`

The custom `/rest/signDoc` endpoint calls these internally:

1. `getCertificates(...)` to select a certificate/key from a token.
2. DSS `getDataToSign(...)` to produce the exact bytes that the token must
   sign for the chosen PAdES/XAdES/CAdES/ASiC form.
3. `signRequest(...)` to sign those bytes with the selected PKCS#11 key.
4. DSS `signDocument(...)` to embed the returned signature into the final
   document/container.

This means `/rest/signDoc` is not a raw "sign these uploaded bytes" protocol.
The document-signature library must participate both before and after the
PKCS#11 signing operation.

Real eGov callers can also use the stock two-step flow directly:

1. `OPTIONS /rest/certificates`
2. `POST /rest/certificates` with an empty body or `{}`
3. server-side/web-app code prepares `dataToSign`
4. `OPTIONS /rest/sign`
5. `POST /rest/sign` with:

```json
{
  "tokenId": { "id": "..." },
  "keyId": "...",
  "toBeSigned": { "bytes": "base64 bytes to sign" },
  "digestAlgorithm": "SHA256"
}
```

`/rest/certificates` returns `Execution<GetCertificate>` and `/rest/sign`
returns `Execution<SignatureResponse>`. Byte arrays and certificates are
base64 strings in JSON.

## Minimal replacement boundary

A compatible local replacement needs:

- A loopback HTTP server with `GET /nexu-info` and `POST /rest/signDoc`.
- For real eGov forms, also `POST /rest/certificates` and `POST /rest/sign`.
- The same JSON request/response envelope used by the demo.
- PKCS#11 certificate discovery and key selection.
- A document signing library that can create data-to-sign and assemble the
  final PAdES/XAdES/CAdES/ASiC output.

For a minimal first version, support should be scoped to:

- `PAdES-BASELINE-B` for PDF with `enveloped` packaging.
- `SHA256`.
- One configured PKCS#11 module, slot, and certificate/key selector.
- PIN supplied through configuration or a local prompt.

Trying to replace DSS with only `pkcs11-tool` is not enough for PAdES/XAdES.
`pkcs11-tool` can produce a cryptographic signature over bytes, but it cannot
construct the PDF/XML/CAdES signed-document structures expected by callers.

## Suggested implementation direction

Use a small new service rather than modernizing the JavaFX/tray application.
Keep the old protocol at the edge, but replace the internals. A non-Java first
implementation is available in this project root.

- HTTP: simple loopback service on `127.0.0.1:9795`.
- PDF signing engine: pyHanko with PKCS#11 support.
- PKCS#11: python-pkcs11 through pyHanko.
- Config: module path, slot/index, certificate/key id or label, PIN handling,
  allowed origins, and port.

For XAdES/CAdES/ASiC, pyHanko is not enough because it is PDF-focused. Those
formats will need a separate maintained library or a different implementation
strategy. The practical first milestone is PDF/PAdES, because that is the
common browser document-signing path and has a viable Python implementation.
