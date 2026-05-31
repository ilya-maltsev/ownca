# Configuration

`/system/configuration/` has two distinct parts:

* **Issuance modes** — a set of toggles, stored in the database, that
  gate which key families, key-generation methods, export formats and
  profile rules are permitted across the application. Edit them here and
  press **Save settings**.
* **Defaults** and **Environment variables** — read-only views of the
  runtime values loaded from environment variables at startup, so you can
  verify the container's environment without shelling in.

## Issuance modes

These toggles are enforced everywhere the corresponding action can
happen: the UI hides or filters the disabled options, **and** the server
rejects requests that try to bypass the UI. The defaults below apply on
first run; change them at any time and press **Save settings**.

| Toggle | Default | Effect when the toggle is **off** |
|---|---|---|
| **Allow server-side key generation** | on | The app will not generate a private key for you — only an uploaded CSR is accepted on the Cert Issue form. See [Issue a certificate](custom_cert_issue.md). |
| **Allow GOST keys** | on | GOST R 34.10-2012 (256 / 512) is removed from the key-algorithm lists for new CAs and certificates. (Also requires `OWNCA_GOST_ENGINE=on` to be usable at all.) See [GOST algorithms](gost_algorithms.md). |
| **Allow RSA keys** | on | RSA (2048 / 4096) is removed from the key-algorithm lists. |
| **Allow ECDSA / Ed25519** | **off** | When on, ECDSA (P-256, P-384) and Ed25519 are offered. Off by default, so out of the box these families cannot be chosen for a new CA or certificate. |
| **Offer `.gost.p12` export** | on | The TK-26 compatible `.gost.p12` download (RFC 9337 + RFC 9548) is hidden on the certificate page and refused by the server. Has no effect unless the key is a GOST key. See [PKCS#12 export](pkcs12_export.md). |
| **Allow free-form certificate issuance** | **off** | A certificate **profile is required** on the Cert Issue form — the "Free-form (no profile)" option is removed and the server rejects profile-less requests. When **on**, free-form issuance is allowed and a profile's KU / EKU / extension / OID constraints can be bypassed. See [Issue a certificate](custom_cert_issue.md). |

> **Where the key-family toggles apply.** The three key-family switches
> (GOST / RSA / ECDSA) gate **both** CA creation (Authorities) and
> end-entity issuance (Cert Issue): the algorithm dropdowns are filtered
> to the enabled families, and the server rejects a disabled family even
> if it is forced into the request. Certificate **renewal** is *not*
> gated — it reuses the existing key, so a certificate issued before a
> family was disabled can still be renewed.

## Defaults panel

A read-only view of the runtime defaults loaded from environment
variables. Nothing on this panel is editable; it shows the values
already in effect.

| Field | Source env var | Meaning |
|---|---|---|
| Storage directory | `OWNCA_STORAGE_DIR` | Filesystem path where CA and cert material is stored. Default `/var/lib/ownca`. |
| Default key algorithm | `OWNCA_DEFAULT_KEY_ALG` | Algorithm pre-selected on the CA / cert forms. See [GOST algorithms](gost_algorithms.md). |
| Default CA validity (days) | `OWNCA_DEFAULT_CA_DAYS` | Lifetime placed in the **Validity (days)** field on the Create CA form (default `3650`). |
| Default cert validity (days) | `OWNCA_DEFAULT_CERT_DAYS` | Lifetime used by certificate renewal when the field is left blank (default `365`). |
| CRL distribution URL | `OWNCA_CRL_DISTRIBUTION` | Informational base URL — not auto-applied to created CAs; the CDP must still be entered on the CA form. |

## Environment-variable reference

The second panel lists the env vars that drive the application,
including ones not surfaced in the cards above:

| Variable | Purpose |
|---|---|
| `OWNCA_STORAGE_DIR` | Storage root for CA / cert files. |
| `OWNCA_OPENSSL_BIN` | Path to the `openssl` binary (gost-engine is loaded via `OPENSSL_CONF`). |
| `OWNCA_DEFAULT_KEY_ALG` | Default key algorithm. |
| `OWNCA_DEFAULT_CA_DAYS` | Default CA validity. |
| `OWNCA_DEFAULT_CERT_DAYS` | Default end-entity validity. |
| `OWNCA_CRL_DISTRIBUTION` | Public URL where CRLs will be served. |
| `OPENSSL_CONF` | Path to `openssl.cnf` that loads gost-engine. |

## Applying changes

**Issuance modes** are saved to the database the moment you press
**Save settings** and take effect on the next request — no restart needed.

The **Defaults** and **Environment variables** are different: they are
read from environment variables at startup. To change them, edit
`dev_env/.env` (or the equivalent file used by `demo/`) and restart the
container — the page picks up the new values on the next request.

## Related topics

* [Issue a certificate](custom_cert_issue.md)
* [Certificate profiles](cert_profiles.md)
* [PKCS#12 export](pkcs12_export.md)
* [Administrator account](users.md)
* [Maintenance](maintenance.md)
