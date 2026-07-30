# X.509 certificate structure

An X.509 v3 certificate is a signed binding between a public key and
the identity that owns it.

## Main fields

| Field | Description |
|---|---|
| Version | OwnCA only issues v3. |
| Serial number | A positive integer unique within the issuer. |
| Issuer / Subject | Distinguished Names of the CA and the owner (CN, O, OU, C, ST, L, …). |
| Validity | `notBefore` and `notAfter` timestamps. |
| Public key | Algorithm and the key itself. |
| Extensions | Optional fields like Key Usage, SAN, distribution points (v3 only). |

## Extensions

Each extension carries an OID, a `critical` flag, and a value. If
`critical=TRUE` the relying party **must** understand the extension,
otherwise the certificate is rejected.

### Common extensions

| OID | Name |
|---|---|
| `2.5.29.14` | Subject Key Identifier |
| `2.5.29.35` | Authority Key Identifier |
| `2.5.29.15` | Key Usage |
| `2.5.29.32` | Certificate Policies |
| `2.5.29.17` | Subject Alternative Name |
| `2.5.29.19` | Basic Constraints |
| `2.5.29.30` | Name Constraints |
| `2.5.29.36` | Policy Constraints |
| `2.5.29.37` | Extended Key Usage — see [Key Usage](key_usage.md) |
| `2.5.29.31` | CRL Distribution Points — see [Distribution points](distribution_points.md) |
| `1.3.6.1.5.5.7.1.1` | Authority Information Access |
| `1.3.6.1.5.5.7.1.11` | Subject Information Access |

## Signature

The certificate is signed by the issuing CA's private key. The
algorithm depends on the CA — RSA, ECDSA, Ed25519, or GOST (see
[GOST algorithms](gost_algorithms.md)).

## Related topics

* [Key Usage and Extended Key Usage](key_usage.md)
* [Distribution points](distribution_points.md)
* [GOST algorithms](gost_algorithms.md)
* [Glossary](glossary.md)
