# Key Usage and Extended Key Usage

These extensions declare how the public key in a certificate may (and
must) be used.

## Key Usage

A bit string. Each bit denotes one operation type.

| Bit | Name | Purpose |
|---|---|---|
| 0 | `digitalSignature` | Signing data unrelated to certificate or CRL signing: TLS handshake, authentication, JWT. |
| 1 | `nonRepudiation` (= `contentCommitment`) | Legally binding signatures (e-signatures of documents). |
| 2 | `keyEncipherment` | Wrapping a symmetric key (key transport). Used in RSA TLS key exchange. |
| 3 | `dataEncipherment` | Direct encryption of user data with the public key. Rarely set in practice. |
| 4 | `keyAgreement` | Shared-secret derivation (Diffie–Hellman, ECDH, GOST VKO). |
| 5 | `keyCertSign` | Signing certificates. **CA only.** |
| 6 | `cRLSign` | Signing CRLs. **CA or dedicated CRL signer only.** |
| 7 | `encipherOnly` | Refines `keyAgreement`: encryption only (only valid when `keyAgreement` is also set). |
| 8 | `decipherOnly` | Likewise — decryption only. |

> Key Usage **should** be `critical=TRUE` whenever the certificate has
> an unambiguous purpose.

### Common combinations

| Use case | Bits |
|---|---|
| TLS server (RSA) | `digitalSignature`, `keyEncipherment` |
| TLS server (ECDSA / GOST) | `digitalSignature` (+`keyAgreement`) |
| TLS client | `digitalSignature` |
| S/MIME signing | `digitalSignature`, `nonRepudiation` |
| S/MIME encryption | `keyEncipherment` |
| Code signing | `digitalSignature` |
| CA | `keyCertSign`, `cRLSign` |

## Extended Key Usage

A list of OIDs naming application purposes. Unlike Key Usage, EKU is
usually `critical=FALSE`, but clients (notably browsers for TLS
server certificates) enforce it strictly.

### Common OIDs

| OID | Name | Purpose |
|---|---|---|
| `1.3.6.1.5.5.7.3.1` | `id-kp-serverAuth` | TLS Server Authentication |
| `1.3.6.1.5.5.7.3.2` | `id-kp-clientAuth` | TLS Client Authentication |
| `1.3.6.1.5.5.7.3.3` | `id-kp-codeSigning` | Code signing |
| `1.3.6.1.5.5.7.3.4` | `id-kp-emailProtection` | S/MIME |
| `1.3.6.1.5.5.7.3.8` | `id-kp-timeStamping` | Time-Stamping Authority |
| `1.3.6.1.5.5.7.3.9` | `id-kp-OCSPSigning` | OCSP responder |
| `2.5.29.37.0` | `anyExtendedKeyUsage` | Any EKU |
| `1.3.6.1.4.1.311.10.3.4` | Microsoft EFS | File encryption |
| `1.2.643.2.2.34.6` | GOST — TLS server | Used in Russia-oriented certificates |

### Combining Key Usage and EKU

During path validation the client checks the **intersection** of
declared purposes. For instance:

* TLS server: KU must include `digitalSignature`; EKU must include
  `serverAuth`.
* If EKU is present without `serverAuth`, TLS-server use is **rejected**
  regardless of KU.

## Where it is configured in OwnCA

* In each [certificate profile](cert_profiles.md) — KU checkboxes
  plus the EKU OID list. When the issuance form on [Custom Cert
  Issue](custom_cert_issue.md) selects a profile, the profile's KU
  and EKU lines win; the form's free-form KU/EKU controls are
  ignored for those attributes (they are still applied to other
  extension lines that the profile leaves blank). Free-form mode (no
  profile) uses the form's checkboxes and EKU string verbatim.

## Related topics

* [X.509 certificate structure](x509_overview.md)

