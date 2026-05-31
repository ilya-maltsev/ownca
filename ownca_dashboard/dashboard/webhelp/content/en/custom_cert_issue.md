# Custom Cert Issue

`/custom-cert-issue/` — issue a certificate **immediately**, without
a CSR review queue. Pick the issuing CA and an optional certificate
profile, fill in any combination of extensions, and click **Issue
certificate**. The certificate is created on the spot and you land
on its detail page.

The page is always reachable from the **Cert Issue** sidebar entry —
there is no feature flag gating it. All actions are performed as the
single superuser account.

## When to use

* Test or service certificates with a non-standard mix of extensions
  that does not justify a dedicated profile.
* Issuing a certificate with a brand-new OID not yet in any profile.
* Experiments — checking how an application reacts to a particular
  `keyUsage` plus a critical `policyConstraints` value.

## Form fields

| Group | What it sets |
|---|---|
| **Issuer CA** | the CA that will sign the certificate (required) |
| **Profile** | optional — picking one auto-loads its KU/EKU/extensions and exposes its custom-OID inputs. Empty = "Free-form (no profile)". |
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

### How profile + free-form interact

When a profile is selected, its rendered extension lines form the
base. Free-form lines from the form are appended only when their
leading attribute (`keyUsage`, `extendedKeyUsage`, …) does not
already appear in the profile's lines. So a profile that sets
`keyUsage` will not be widened by the form's KU checkboxes; but
profile lines and form lines that touch different attributes are
combined.

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
