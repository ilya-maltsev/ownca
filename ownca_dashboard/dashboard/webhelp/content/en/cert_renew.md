# Certificate renewal

The **Renew** button on the certificate detail page re-signs the
original CSR as a new certificate. The subject DN, key algorithm,
profile, and OID field values are preserved; only the validity dates
and serial number change.

## How renewal works

1. The original CSR is re-signed by the issuing CA using the same
   extension profile and distribution-point URLs.
2. A new certificate is created and linked to the previous one.
3. The old certificate **remains active** — it is not revoked
   automatically. Revoke it explicitly if you no longer want it
   trusted (see [Revocation and CRL](cert_revoke.md)).

## Prerequisites

* The original CSR must still be present on disk. If it has been
  deleted, the renewal will fail.

## Validity period

The **Days** field on the renewal form controls the new certificate's
lifetime. Defaults to the value of `OWNCA_DEFAULT_CERT_DAYS`.

## Chain and download

The renewed certificate appears immediately on the certificate detail
page. Download it in PEM, chain bundle, or PKCS#12 format — see
[PKCS#12 export](pkcs12_export.md).

## Related topics

* [Certificate registry](certificates.md)
* [Revocation and CRL](cert_revoke.md)
* [PKCS#12 export](pkcs12_export.md)
