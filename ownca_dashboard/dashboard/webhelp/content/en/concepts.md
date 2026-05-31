# PKI concepts

A short summary of the terms that OwnCA is built on.

## X.509 certificate

A digital document that binds a public key to a subject identifier
(subject DN), signed by a certification authority (issuer). The most
important fields:

* Serial number — unique identifier within the CA.
* Subject / Issuer — Distinguished Names.
* Validity — `notBefore` / `notAfter`.
* Public key — the bound key and its algorithm.
* Extensions — Key Usage, SAN, distribution points, etc.

## Certification Authority (CA)

The entity that issues certificates. Two types:

* **Root CA** — self-signed; the trust anchor.
* **Intermediate CA** — issued by another CA; used to issue
  end-entity certificates while keeping the root key offline.

## Certificate signing request (CSR / PKCS#10)

A container with a public key and subject DN, signed by the
requester's private key. OwnCA accepts CSRs in **PEM** form (the
issuance form takes a pasted PEM block or an uploaded `.csr` /
`.pem` / `.req` / `.txt` file). DER input is not supported — convert
with `openssl req -inform DER -outform PEM` first.

## Certificate extensions

Fields that extend the base X.509 model. The most important:

* **Key Usage** — operations allowed for the key.
* **Extended Key Usage** — application-level purposes (TLS server,
  TLS client, code signing, etc.).
* **Subject Alternative Name** — DNS names, IPs, etc.
* **CDP / AIA / SIA** — distribution points for CRLs, the OCSP
  responder, and CA repositories. See [Distribution
  points](distribution_points.md).
* **Certificate Policies** — issuance policies referenced by OID.

## CRL and OCSP

* **CRL** — Certificate Revocation List; a CA-signed list of revoked
  certificates, published periodically.
* **OCSP** — Online Certificate Status Protocol; an online status
  check for a single certificate.

## Certificate profile

In OwnCA — a template that fixes the set of extensions (Key Usage,
EKU, policies, OID fields, distribution-point overrides). Profiles
are global — they are not bound to a specific CA. The issuance form
asks you to pick both an issuing CA and a profile, and resolves CDP
/ AIA / OCSP / SIA / freshestCRL with profile-overrides-CA
precedence. See [Certificate profiles](cert_profiles.md).

## Roles

OwnCA runs with a single account — the **superuser**. There are no
separate roles; every action (creating CAs, filling in subject and
extensions, issuing, revoking) is performed under that one account.

There is no review queue and no approval step: a certificate is
created the moment the issue form is submitted.

## Lifecycle

```
[Issue form] → [Issuance] → [Active certificate]
                                    ↓
              [Expiry] | [Revocation] | [Renewal]
```

See also the [Glossary](glossary.md).
