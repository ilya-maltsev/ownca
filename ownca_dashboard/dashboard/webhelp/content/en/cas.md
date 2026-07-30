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
| Algorithm | `gost2012_256`, `gost2012_512`, `rsa:2048`, `rsa:4096`, `ec:P-256`, `ec:P-384`, `ed25519`. The CA's algorithm fixes its **key family** (`gost`, `rsa`, `ec`, `ed25519`) and therefore which leaf certificates it may sign — see [Custom Cert Issue](custom_cert_issue.md). With Type = Intermediate the list narrows to the selected parent's family: the parent signs the intermediate's certificate, so GOST and RSA never mix within one chain. |
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

## Importing an existing CA

The **Import existing authority** form (below the create form) registers
a CA that was generated elsewhere so OwnCA can sign certificates with it.
Supply the CA **certificate and its matching private key** — either as two
separate files/PEM blocks, or as a single **PKCS#12 (`.pfx` / `.p12`)
container** that bundles both. OwnCA validates the pair, lays out the
on-disk CA directory, and the authority is immediately usable for issuance
and CRL generation.

| Field | Purpose |
|---|---|
| Name * | Internal identifier for the imported authority. |
| Certificate | The CA certificate, **PEM or DER** (file upload or pasted text). Must carry `basicConstraints CA:TRUE`. |
| Private key | The matching CA private key, **PEM or DER**. Required — an imported CA is a *signing* authority. |
| PKCS#12 container | A `.pfx` / `.p12` file holding the certificate **and** the private key. When supplied it **replaces** the separate certificate/key fields; only the certificate whose key is in the container is imported (extra chain certs are ignored). |
| Key / PKCS#12 passphrase | The password protecting the private key or the PKCS#12 container. Supplied only when the material is encrypted. |
| Parent CA | Optional. For an imported intermediate, links it to a parent already in OwnCA (for chain building). The parent must be of the same key family as the imported certificate: a GOST CA cannot have issued an RSA certificate. Leave it empty when the real issuer is not managed here. |

On import OwnCA automatically **detects the key algorithm** from the
certificate (GOST 256/512, RSA, EC P-256/P-384, Ed25519), **detects the
type** (a self-signed certificate is stored as root, otherwise
intermediate), and **verifies** the certificate is a CA whose private key
matches it — mismatched or non-CA material is rejected. PKCS#12 files
sealed with older ciphers (RC2-40 / 3DES, e.g. exports from Windows) are
read via OpenSSL's legacy provider automatically. The imported key
algorithm must be permitted by the current issuance-mode settings.

The key family is taken from **the public key of the certificate inside
the container**, not from the type of provider the key landed in: a
container holding a non-GOST key is refused on the CryptoPro import path
rather than recorded as a GOST CA. Otherwise you would end up with a CA
that declares GOST and offers GOST algorithms for an RSA key.

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
* **Export PKCS#12** — bundle the CA cert + key into a password-protected
  `.p12`; see below.
* **Regenerate CRL** — produces a fresh CRL and adds an entry to the
  CRL export history.
* **Download CRL** — fetches the latest CRL (auto-generates one if
  none exists yet).
* **Delete** — only succeeds when the CA has **no child CAs and no
  issued certificates at all**. Revoked and expired certificates
  count too — you must delete them first.

A CryptoPro CSP-backed CA gets a **Delete the key container too**
checkbox next to the button, **unticked by default**. The private key
lives in the provider's keystore, outside the data volume, so removing
the directory does not touch it by itself.

* **Unticked** — the container stays in the keystore. Nothing points at
  it any more: the link to the CA lived in the directory that was just
  removed, so only its name can find it.
* **Ticked** — the container goes with the directory. Irreversibly: the
  key is non-exportable, a backup of the storage directory will not bring
  it back, and no CRL can ever be issued again for certificates this CA
  signed. The confirmation says so explicitly.

The same checkbox is on the certificate page when the key was generated
server-side (a certificate issued from an external CSR has no container
of its own). A container that a renewal also references — a renewed
certificate reuses the same key — is kept until the last reference is
deleted, checkbox or not.

When a creation is **rolled back** — a failed CA generation, a rejected
import, an issuance that did not complete — the container is always
dropped, no question asked: no record it could belong to ever appeared.

### Exporting a CA as PKCS#12

**Export PKCS#12** bundles the CA's own certificate and private key into a
single password-protected `.p12` (PFX) file — the counterpart to the
**Importing an existing CA** flow above. Set a passphrase, pick the
bag-encryption / MAC **suite**, and (for an intermediate) optionally tick
**Include chain** to add the parent CA certificates.

| Suite | Bag PBE / MAC | Use for |
|---|---|---|
| Standard (AES-256) | AES-256-CBC bags, SHA-256 MAC | The interoperable default — any modern PKCS#12 reader. |
| GOST Kuznyechik | `kuznyechik-ctr-acpkm` / `md_gost12_512` | TK-26 (RFC 9337 / 9548) — modern GOST software. |
| GOST Magma | `magma-ctr-acpkm-omac` / `md_gost12_256` | TK-26, Magma variant. |
| GOST 28147-89 (legacy) | `gost89` / `md_gost94` | Older CryptoPro-era tools that predate TK-26. |

The GOST suites are produced by the bundled gost-engine and require the
importing software to understand the matching GOST PKCS#12 wire format.
The private key leaves the server inside the exported file — treat it with
the same care as the on-disk key.

## CRL

A CRL is regenerated automatically whenever a certificate is revoked
under this CA, and on demand via **Regenerate CRL**. Each generation
is recorded as a `CrlExport` entry. See [Revocation and
CRL](cert_revoke.md) for the full lifecycle.

## Key safety

CA private keys live under the directory set by `OWNCA_STORAGE_DIR`
(default `/var/lib/ownca/`). Backing this directory up is mandatory.

> **The backend choice is irreversible.** With CryptoPro CSP enabled a new
> GOST CA is created on the certified provider and its key stays in a
> container for good. For what such a CA cannot do, see
> [CryptoPro CSP backend](cryptopro.md).

## Related topics

* [CryptoPro CSP backend](cryptopro.md)
* [Certificate profiles](cert_profiles.md) — what may be issued by this CA.
* [Distribution points](distribution_points.md)
