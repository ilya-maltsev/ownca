# Certificate registry

`/certificates/` — table of every issued certificate, plus the entry
point to per-certificate operations (view, revoke, renew, delete,
download).

## Filters

Two dropdowns at the top of the page:

* **CA** — restrict to certificates issued by a specific CA.
* **Status** — `active`, `revoked`, or `expired`.

There is no per-column search and no global search box.

## Columns

| Column | Description |
|---|---|
| Common Name | Subject CN — links to the certificate detail page. |
| Issuer CA | Issuing CA — links to the CA detail page. |
| Profile | Snapshot of the [profile](cert_profiles.md) display name at issue time. |
| Algorithm | Key algorithm. |
| Serial | Hex serial number. |
| Valid Until | `notAfter`. |
| Status | `Active` / `Revoked` / `Expired`. |

To act on a certificate (revoke / renew / delete / download), open
its detail page from the Common Name link.

## Detail page

`/certificates/<uuid>/` shows:

* The toolbar — **Download cert**, **Download key** (when stored
  server-side), **Download CSR**, **Download PEM bundle**, **Export
  PKCS#12**, **Renew**, **Revoke**, **Delete**.
* A details panel with subject, status, issuer CA, profile,
  algorithm, serial, SHA-256 fingerprint, validity, SAN DNS / IP,
  per-OID custom values, private-key state, revocation info, and the
  source certificate when this is a renewal.
* A **Renewals issued from this certificate** panel, when applicable.
* The full `openssl x509 -text` dump in an **X.509 details** panel.

The page does not currently render a separate audit-history section
or a graphical chain view.

## Revoke

The **Revoke** button reveals an inline form (no modal) with a
reason-code selector:

| Reason | When to use |
|---|---|
| `unspecified` | No specific reason. |
| `keyCompromise` | The private key has been compromised. |
| `CACompromise` | The CA key has been compromised. |
| `affiliationChanged` | Owner organisation changed. |
| `superseded` | Replaced by a new certificate. |
| `cessationOfOperation` | Operations ceased. |
| `certificateHold` | Temporary suspension. |

On confirmation the certificate is marked revoked, a fresh CRL is
generated and a new CRL export entry is logged.

## Renew

The **Renew** button reveals an inline form with a **Days** input.
The new certificate is signed by the same CA, reusing the original
CSR (and key, if stored) and the original profile / OID values; only
the validity dates and serial change. The previous certificate is
left untouched — revoke it explicitly if you no longer want it
trusted.

The original CSR file must still be present on disk; otherwise the
renewal fails.

## Delete

The **Delete** button removes the database row and the on-disk
certificate / key / CSR files. There is **no status restriction** —
active certificates can be deleted too. Use revocation instead when
you want a CRL entry; deletion only removes the registry record.

## Related topics

* [Certificate renewal](cert_renew.md)
* [Revocation and CRL](cert_revoke.md)
* [PKCS#12 export](pkcs12_export.md)
* [CA management](cas.md)
