# Distribution points (CDP / AIA / SIA)

Certificates carry several extensions that say where to fetch related
artefacts.

## CRL Distribution Points (CDP)

One or more URLs at which the CRL — the list of certificates revoked
by the same CA — is published. During path validation the relying
party fetches the CRL and checks whether the certificate's serial
appears in it.

In OwnCA the URL is set:

* On the CA itself (the `crl_url` field, see [CA management](cas.md)).
* On the [certificate profile](cert_profiles.md) — overrides the CA
  value for specific certificate categories.

> Omitting CDP is allowed for CAs that rely solely on OCSP, but most
> TLS clients require CDP to be present.

## Authority Information Access (AIA)

Names two access methods:

* **`caIssuers`** — where to fetch the issuer's CA certificate (used
  for chain building).
* **OCSP** — OCSP responder URL.

In OwnCA — the `aia_url` and `ocsp_url` fields on the CA.

## Subject Information Access (SIA)

Used mostly in **CA** certificates: points at the repository of the
certificates that CA has issued.

In OwnCA — the `sia_url` field on [CA management](cas.md).

## Freshest CRL (Delta CRL Distribution Point)

URL of the **delta CRL** — a partial revocation list between full
publications. Backed by the `freshest_crl_url` field.

## Issuer Alternative Names

Additional CA names in the same forms as SAN (DNS, URI, e-mail …).
In OwnCA — the `issuer_alt_names` field on the CA.

## Resolution in OwnCA

At issue time OwnCA applies a precedence rule:

1. **Certificate profile** (when the field is set there).
2. **CA** (values from the CA card).
3. Empty value → the extension is omitted.

## Related topics

* [X.509 certificate structure](x509_overview.md)
* [CA management](cas.md)
