# CA management

`/cas/` — root and intermediate certification authorities. The page
combines an inline **Create new authority** form with the CA list.

## CA list

| Column | Description |
|---|---|
| Name | Internal name (used in URLs and UI). |
| Type | `Root CA` / `Intermediate CA`. |
| Parent | The parent CA when this CA is intermediate. |
| Algorithm | Key algorithm. |
| Issued | Number of certificates this CA has issued. |
| Valid Until | `notAfter` of the CA certificate. |
| Status | `Active` (when `is_enabled`) or `Disabled`. |

## Creating a CA

The **Create new authority** form sits above the list — there is no
"open form" button; it is always visible. Two scenarios:

1. **Root CA** — generates a self-signed certificate.
2. **Intermediate CA** — choose **Type = Intermediate CA** to reveal
   the **Parent CA** selector; OwnCA produces a CSR, signs it with
   the parent, and stores the chain.

### Form fields

| Field | Purpose |
|---|---|
| Name * | Internal identifier (used in URLs and UI). |
| Common Name * | CN of the CA's subject DN. |
| Type | `Root CA` or `Intermediate CA`. |
| Parent CA | Required when Type = Intermediate. |
| Algorithm | `gost2012_256`, `gost2012_512`, `rsa:2048`, `rsa:4096`, `ec:P-256`, `ec:P-384`, `ed25519`. The CA's algorithm fixes its **key family** (`gost`, `rsa`, `ec`, `ed25519`) and therefore which leaf certificates it may sign — see [Custom Cert Issue](custom_cert_issue.md). |
| Validity (days) | CA lifetime — defaults to `OWNCA_DEFAULT_CA_DAYS`. |
| Path length | Maximum chain depth below this CA (blank = no constraint). |
| CRL Distribution Point URL | CDP embedded in issued certs. |
| AIA caIssuers URL | Where to fetch this CA's certificate. |
| OCSP responder URL | OCSP URL. |
| SIA caRepository URL | Subject Information Access (mostly for sub-CAs). |
| Freshest CRL URL | Delta-CRL URL. |
| issuerAltName entries | One openssl entry per line (e.g. `email:ca@example.org`). |
| Country / State / Locality / Organization / Unit | Optional subject DN attributes. |

See [Distribution points](distribution_points.md) for the precedence
rules between CA values and per-profile overrides.

## CA detail page

`/cas/<uuid>/` shows:

* Toolbar: **Download CA cert**, **Download CRL**, **Regenerate
  CRL**, **Delete**.
* **Authority details** panel — all CA fields including current CRL
  number, every distribution-point URL, and the issued-certificates
  count broken out into active / revoked.
* **Distribution points** panel — an editable form to update
  `crl_url`, `aia_url`, `ocsp_url`, `sia_url`, `freshest_crl_url`,
  and `issuerAltName` after creation. Changes apply to certificates
  issued from that point on.
* The full `openssl x509 -text` dump of the CA certificate.

### Buttons in detail

* **Download CA cert** — PEM file of the CA certificate.
* **Regenerate CRL** — produces a fresh CRL and adds an entry to the
  CRL export history.
* **Download CRL** — fetches the latest CRL (auto-generates one if
  none exists yet).
* **Delete** — only succeeds when the CA has **no child CAs and no
  issued certificates at all**. Revoked and expired certificates
  count too — you must delete them first.

## CRL

A CRL is regenerated automatically whenever a certificate is revoked
under this CA, and on demand via **Regenerate CRL**. Each generation
is recorded as a `CrlExport` entry. See [Revocation and
CRL](cert_revoke.md) for the full lifecycle.

## Key safety

CA private keys live under the directory set by `OWNCA_STORAGE_DIR`
(default `/var/lib/ownca/`). Backing this directory up is mandatory.

## Related topics

* [Certificate profiles](cert_profiles.md) — what may be issued by this CA.
* [Distribution points](distribution_points.md)
