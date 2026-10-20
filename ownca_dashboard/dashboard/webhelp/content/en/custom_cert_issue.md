# Custom Cert Issue

`/custom-cert-issue/` — issue a certificate **immediately**, without
a CSR review queue. Pick the issuing CA and a certificate profile,
fill in the extensions you need, and click **Issue certificate**. The
certificate is created on the spot and its detail page opens.

The page is always reachable from the **Cert Issue** sidebar entry.
All actions are performed as the single superuser account.

A profile is **required** by default. Issuing without a profile
(free-form mode) must first be allowed on the
[Configuration](configuration.md) page with the **Allow free-form
certificate issuance** toggle.

## When free-form mode is useful

* Test or service certificates with a non-standard mix of extensions
  that does not justify a dedicated profile.
* Issuing a certificate with a brand-new OID not yet in any profile.
* Experiments — checking how an application reacts to a particular
  `keyUsage` plus a critical `policyConstraints` value.

## Form fields

| Group | What it sets |
|---|---|
| **Issuer CA** | the CA that will sign the certificate (required) |
| **Profile** | picking one auto-loads its KU/EKU/extensions and exposes its custom-OID inputs. The "Free-form (no profile)" option is there only when free-form issuance is allowed in Configuration. |
| **Key & validity** | algorithm (`gost2012_256`, RSA, ECDSA, …) with a GOST paramset selector that appears for GOST keys; validity in days. The dropdown shows only algorithms compatible with the issuing CA — see *CA / key family compatibility* below |
| **Subject** | CN (required), C, ST, L, O, OU |
| **Subject Alternative Names** | DNS, IP, e-mail, URI, otherName (one per line for the multi-value fields) |
| **Key Usage** | a checkbox per bit plus the criticality flag (free-form path; ignored when a profile already sets KU) |
| **Extended Key Usage** | free-form string (`serverAuth, clientAuth, …`) plus the criticality flag (same precedence rule) |
| **Distribution-point overrides** | `crl_url`, `aia_url`, `ocsp_url`, `sia_url`, `freshest_crl_url` — empty inherits from the issuing CA |
| **Key identifiers** | toggles for `subjectKeyIdentifier`, `authorityKeyIdentifier`, and `AKI include issuer:always` |
| **Custom OID values** | rows of *(OID, ASN.1 type, value)* for free-form mode; required-flagged inputs for profile-defined OIDs |
| **Extra extension lines** | free text added verbatim to the certificate extensions |
| **External CSR** | optional PEM CSR upload (or pasted text) — when provided, the server signs that CSR and no key is generated |

### CA / key family compatibility

A CA can only sign certificates whose key algorithm belongs to the
**same cryptographic family** as the CA's own key. Families are:

| Family | Members |
|---|---|
| `gost` | `gost2012_256`, `gost2012_512` |
| `rsa` | `rsa:2048`, `rsa:4096` |
| `ec` | `ec:P-256`, `ec:P-384` |
| `ed25519` | `ed25519` |

Selecting an issuing CA in the form filters the **Algorithm**
dropdown to its family — incompatible options are hidden, and a
previously-chosen value is replaced with the first allowed one. The
backend re-validates on submit; a request that smuggles an
incompatible `key_alg` is rejected with the message *"Key algorithm
… is not compatible with the issuing CA"* and no certificate is
created.

When an external CSR is attached, the family comes from **the CSR's
own public key**, not from the form's dropdown — that dropdown may
be left over from an earlier parse and no longer describe the
attached file. Only the request's public key is read, so the CSR's
signature algorithm cannot skew the result. A mismatch is refused
before issuance, so an RSA request can never be signed by a GOST
CA's key or vice versa. "Parse CSR" reports the mismatch up front,
before the form is submitted.

A parent CA signs its intermediate's certificate, so the same rule
applies when creating an intermediate on the
[Authorities](cas.md) page.

### How the profile and the form fields combine

When a profile is selected, its extensions form the base. A line from
the form fields is added only if the profile does **not** set the
extension that line starts with (`keyUsage`, `extendedKeyUsage`, …).
For example, if the profile sets `keyUsage`, the form's KU checkboxes
do not add to it; extensions the profile does not set are taken from
the form.

CA-resolved fields (CDP / AIA / OCSP / SIA / freshestCRL,
issuerAltName) follow the precedence rule: profile value wins, CA
value falls back, blank → omit.

## What happens on submit

1. The form's selections are combined with the chosen profile (if
   any) into the final extension set.
2. Required custom-OID fields declared by the profile are validated.
3. The certificate is signed by the issuing CA.
4. On success you are redirected to the certificate detail page,
   where you can download the cert, key, CSR, PEM bundle, or a
   PKCS#12 archive.

## Related topics

* [Certificate profiles](cert_profiles.md) — the structured issuance path
* [Certificates](certificates.md)
* [CSR parse helper](csr_parse.md) — what gets extracted from an uploaded CSR
