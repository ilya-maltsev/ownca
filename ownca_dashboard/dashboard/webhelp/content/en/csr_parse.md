# CSR parse helper

The CSR parser is an internal helper used by the [Custom Cert
Issue](custom_cert_issue.md) form. There is no standalone "CSR parse"
page; the endpoint at `/certificates/csr-parse/` is an
authenticated AJAX endpoint that accepts a PEM CSR and returns the
decoded fields as JSON. The Cert Issue form posts the CSR there and
uses the response to auto-fill subject / SAN fields and to display
the raw text.

## What the parser extracts

The endpoint returns the following keys (empty string / empty list
when an attribute is absent):

| Field | Description |
|---|---|
| `common_name` | CN attribute from the subject DN. |
| `country` / `state` / `locality` / `organization` / `unit` | Other subject DN attributes. |
| `public_key_algorithm` | For example `rsaEncryption`, `id-ecPublicKey`, `GOST R 34.10-2012`. |
| `signature_algorithm` | Algorithm used to sign the CSR itself. |
| `paramset` / `paramset_raw` | GOST parameter set identifier (`A` / `B` / `C` / `XA` / `XB`) and the raw OID label as openssl printed it. |
| `san_dns` | Subject Alternative Name DNS entries. |
| `san_ip` | Subject Alternative Name IP entries. |
| `requested_ku` | Key Usage bits requested in the CSR (informational only). |
| `requested_eku` | Extended Key Usage OIDs requested in the CSR (informational only). |
| `raw_text` | Full `openssl req -text -noout` dump for display. |

Other SAN types (email, URI, otherName) are not parsed out by this
helper. If your CSR carries them and you need them on the issued
cert, enter them manually in the Custom Cert Issue form's SAN
fields.

Input must be PEM. DER input is not supported.

> **Security note.** CSR-requested extensions are always dropped at
> signing time. The parser output is informational — it shows what
> the CSR *asked for*, not what will end up in the issued
> certificate. Extensions come from the selected profile and the
> free-form controls on the issue form.

## Related topics

* [Custom Cert Issue](custom_cert_issue.md)
* [Certificate registry](certificates.md)
