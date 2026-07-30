# Glossary

| Term | Definition |
|---|---|
| **AIA** | Authority Information Access — X.509 extension carrying URLs of the OCSP responder and the issuer's CA certificate. |
| **ASN.1** | Abstract Syntax Notation One — the notation in which X.509 objects are formally described. |
| **CA** | Certification Authority. |
| **CDP** | CRL Distribution Points — X.509 extension listing CRL URLs. |
| **CN** | Common Name — DN attribute, often the owner's name, e-mail, or DNS hostname. |
| **CRL** | Certificate Revocation List — CA-signed list of revoked certificates. |
| **CSR** | Certificate Signing Request (PKCS#10). |
| **DER** | Distinguished Encoding Rules — binary ASN.1 encoding; the wire format for certificates. |
| **DN** | Distinguished Name — sequence of RDN attributes identifying subject or issuer. |
| **EKU** | Extended Key Usage — X.509 extension listing application-purpose OIDs. |
| **End-entity** | A leaf certificate issued to a user or service, not a CA. |
| **Issuer** | The party that signed a certificate. |
| **Key Usage (KU)** | X.509 extension whose bit string declares allowed key operations. |
| **OCSP** | Online Certificate Status Protocol — online status check for a single certificate. |
| **OID** | Object Identifier — unique identifier; every X.509 extension has its own. |
| **PEM** | Privacy-Enhanced Mail — Base64 wrapper around DER with `-----BEGIN ...-----` headers. |
| **PKCS#7** | Cryptographic container holding one or more certificates. |
| **PKCS#10** | CSR format. |
| **PKCS#12** | Password-protected container with certificate and private key. |
| **Path validation** | The process of verifying a certificate chain up to a trusted root. |
| **PKI** | Public Key Infrastructure — the collective of CAs, policies, software, and processes for issuing certificates. |
| **Profile** | In OwnCA — a template of certificate extensions. |
| **RDN** | Relative Distinguished Name — one DN attribute. |
| **Root CA** | A self-signed CA at the top of a chain. |
| **SAN** | Subject Alternative Name — X.509 extension with alternative owner names: DNS, IP, e-mail, URI. |
| **Serial number** | A number unique within the issuer that identifies a certificate. |
| **SIA** | Subject Information Access — X.509 extension with the URL of the subject CA's repository. |
| **SKI / AKI** | Subject Key Identifier / Authority Key Identifier — extensions with key-derived identifiers. |
| **Subject** | The entity to whom a certificate was issued. |
| **TSA** | Time-Stamping Authority. |
| **VKO** | Russian shared-secret derivation algorithm in GOST R 34.10-2012. |
| **X.509** | The standard for public-key certificates. |
| **GOST R 34.10-2012** | Russian elliptic-curve digital signature standard. |
| **GOST R 34.11-2012 ("Streebog")** | Russian hash function, 256 and 512 bits. |

See also [PKI concepts](concepts.md), [X.509 certificate structure](x509_overview.md).
