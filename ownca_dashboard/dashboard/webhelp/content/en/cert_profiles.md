# Certificate profiles

`/cert-profiles/` — templates of certificate extensions. A profile
fixes which Key Usage / Extended Key Usage and custom OID fields end
up in an issued certificate.

Profiles are **global** — they are not bound to a specific CA. Any
profile can be used with any CA on the issuance form.

## Profile list

| Column | Description |
|---|---|
| Name | Internal identifier (slug, `[a-z0-9_]+`). |
| Display name | Human-readable name. |
| Description | Free-form text. |
| Key Usage | Compact KU summary (e.g. `dS, kE`). |
| Extended Key Usage | EKU string. |
| CA | `CA` badge when the profile is a CA profile (basicConstraints CA:TRUE). |
| In use | `<certs> / <pending requests>`. |

## Profile structure

### Key Usage

A bit string declaring which operations the key can perform:

* `digitalSignature` — signing data (handshake, JWT, …).
* `nonRepudiation` (`contentCommitment`) — legally binding signatures.
* `keyEncipherment` — wrapping a symmetric key.
* `dataEncipherment` — encrypting application data directly.
* `keyAgreement` — shared-secret derivation (DH/ECDH/VKO).
* `keyCertSign` — signing certificates (CA only).
* `cRLSign` — signing CRLs.
* `encipherOnly` / `decipherOnly` — refinements of `keyAgreement`.

See [Key Usage and Extended Key Usage](key_usage.md).

### Extended Key Usage

OIDs naming application purposes. Common ones:

| OID | Purpose |
|---|---|
| `1.3.6.1.5.5.7.3.1` | TLS Server Authentication |
| `1.3.6.1.5.5.7.3.2` | TLS Client Authentication |
| `1.3.6.1.5.5.7.3.3` | Code Signing |
| `1.3.6.1.5.5.7.3.4` | Email Protection (S/MIME) |
| `1.3.6.1.5.5.7.3.8` | Time Stamping |
| `1.3.6.1.5.5.7.3.9` | OCSP Signing |

### Custom OID fields

A profile can be linked to entries in the custom OID registry. Each
entry describes a single subject DN attribute, SAN element, or
arbitrary extension filled in at issuance.

### Other parameters

| Field | Description |
|---|---|
| Is CA profile | When enabled, the profile emits `basicConstraints = CA:TRUE` — for intermediate CA certs. |
| Extra extensions | Raw extension lines appended verbatim to the certificate's extension section. |

## Copy button

A **Copy** button sits next to **Delete** on the profile editor page.
It creates a full duplicate of the current profile (including its
custom-OID field links) under a unique name and redirects to the
editor of the new copy — a fast way to spawn a variant of an existing
profile.

## Related topics

* [Key Usage](key_usage.md)
