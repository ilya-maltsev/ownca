# GOST algorithms

OwnCA supports issuing certificates signed under Russian cryptographic
standards.

## Standards

| Standard | Purpose | Hash |
|---|---|---|
| **GOST R 34.10-2012** | Elliptic-curve digital signature. | — |
| **GOST R 34.11-2012** ("Streebog") | Hash function, 256 or 512 bits. | used in the signature |
| **GOST 28147-89**, **GOST R 34.12-2015** (Kuznyechik, Magma) | Symmetric encryption (used for PKCS#12 export). | — |

OwnCA uses these in X.509:

| Parameter | 256-bit | 512-bit |
|---|---|---|
| Key algorithm OID | `1.2.643.7.1.1.1.1` | `1.2.643.7.1.1.1.2` |
| Signature algorithm OID | `1.2.643.7.1.1.3.2` | `1.2.643.7.1.1.3.3` |
| Hash | GOST R 34.11-2012 / 256 | GOST R 34.11-2012 / 512 |
| Public key length | 512 bits (two 256-bit coordinates) | 1024 bits |

## Curve parameters

The default parameter set is **A**: for `gost2012_256` that is
CryptoPro-A (`1.2.643.2.2.35.1`), for `gost2012_512` the TC 26 paramSetA
(`1.2.643.7.1.2.1.2.1`). Another set can be picked on the form: `A`,
`B`, `C`, `XA`, `XB` for 256-bit keys, `A`, `B`, `C` for 512-bit keys.

The full list of recommended parameter sets is published by
[TC 26](https://tc26.ru/).

## Compatibility

* OpenSSL 1.1+, 3.x — through gost-engine.
* CryptoPro CSP 4.0+ — accepts certificates and signatures produced by
  OwnCA.
* The bundled nginx (OpenSSL + gost-engine) — TLS with the
  `GOST2012-KUZNYECHIK-KUZNYECHIKOMAC` and `GOST2012-MAGMA-MAGMAOMAC`
  cipher suites.

## Where used in OwnCA

* On [CA management](cas.md) — the CA's key algorithm.
* On [Custom Cert Issue](custom_cert_issue.md) — the certificate's
  key algorithm comes from the CSR or, when the server generates the
  key, is chosen on the form (the default algorithm is pre-selected).
* The `OWNCA_DEFAULT_KEY_ALG` environment variable carries the
  default — see [Configuration](configuration.md).

## Related topics

* [X.509 certificate structure](x509_overview.md)
* [Glossary](glossary.md)
