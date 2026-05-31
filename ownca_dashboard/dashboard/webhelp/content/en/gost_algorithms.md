# GOST algorithms

OwnCA supports issuing certificates signed under Russian cryptographic
standards.

## Standards

| Standard | Purpose | Hash |
|---|---|---|
| **GOST R 34.10-2012** | Elliptic-curve digital signature. | — |
| **GOST R 34.11-2012** ("Streebog") | Hash function, 256 or 512 bits. | used in the signature |
| **GOST 28147-89** / **Kuznyechik (R 34.12-2015)** | Symmetric encryption. | — |

OwnCA uses these in X.509:

| Parameter | 256-bit | 512-bit |
|---|---|---|
| Key algorithm OID | `1.2.643.7.1.1.1.1` | `1.2.643.7.1.1.1.2` |
| Signature algorithm OID | `1.2.643.7.1.1.3.2` | `1.2.643.7.1.1.3.3` |
| Hash | GOST R 34.11-2012 / 256 | GOST R 34.11-2012 / 512 |
| Public key length | 512 bits (two 256-bit coordinates) | 1024 bits |

## Curve parameters

For `gost2012_256` OwnCA defaults to **paramSetA**
(`1.2.643.7.1.2.1.1.1`). For `gost2012_512` — **paramSetA**
(`1.2.643.7.1.2.1.2.1`).

The full list of recommended parameter sets is published by
[TC 26](https://tc26.ru/).

## Compatibility

* OpenSSL 1.1+, 3.x — through gost-engine.
* CryptoPro CSP 4.0+ — interoperable on certificate format and
  signature.
* nginx with the gost-tls patch — supports the
  `GOSTR341112-256-CNT-MAC` and `KUZNYECHIK-CTR-OMAC` cipher suites.

## Where used in OwnCA

* On [CA management](cas.md) — the CA's key algorithm.
* On [Custom Cert Issue](custom_cert_issue.md) — the certificate's
  key algorithm comes from the CSR or, when the server generates the
  key, from the default algorithm.
* The `OWNCA_DEFAULT_KEY_ALG` environment variable carries the
  default — see [Configuration](configuration.md).

## Related topics

* [X.509 certificate structure](x509_overview.md)
* [Glossary](glossary.md)
