# OwnCA Dashboard

[Русский](README.md) | **English**

---

Web UI for managing a Certificate Authority that issues certificates using
[gost-engine](https://github.com/gost-engine/engine) (GOST R 34.10-2012 / GOST R
34.11-2012). Supports filtering, revocation, renewal, and PKCS#12 export.

## Features

- **Certificate Authorities** — create root and intermediate CAs (GOST or RSA),
  view subject/issuer/serial/fingerprint/dates, download the CA cert.
- **Certificates** — list issued certs filtered by CA and status, view full
  X.509 details, download cert / key / CSR / PEM bundle / PKCS#12, revoke with
  reason, renew.
- **Cert Issue** — pick a CA + optional profile, fill in Subject DN + SANs,
  generate a keypair server-side or upload an external CSR. Free-form mode
  allows arbitrary KU / EKU / extensions / OIDs without a profile.
- **Cert Profiles** — extension templates (KU, EKU, basicConstraints, name
  constraints, policy constraints, distribution-point overrides, custom OID
  fields).
- **CRL** — auto-regenerated on every revocation, manual regeneration on the
  CA detail page, downloadable as PEM. "Rebuild all CRLs" (Maintenance) also
  publishes every enabled CA's CRL to `crls/<ca_name>.crl`.
- **System** — Configuration page (env-var summary), Maintenance (openssl
  version, gost-engine status, on-disk metadata refresh, rebuild-all-CRLs).
- **Webhelp** — bundled contextual help portal at `/webhelp/`.
- **i18n** — Russian (default) and English, switchable in the sidebar.
- **Authentication** — login with a single admin account provisioned from
  environment variables.

## Architecture

```
                       nginx :8443 (GOST + RSA TLS)
                              |
Browser -----> nginx ------> Dashboard :8000
                                   |
                                   |--> PostgreSQL :5432  (metadata index)
                                   |
                                   |--> /var/lib/ownca/   (keys, certs, CRLs)
```

All key/cert material lives on disk in the storage directory; the database
holds only the metadata index for fast filtering and listing.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `DB_HOST` | `127.0.0.1` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `ownca` | Database name |
| `DB_USER` | `ownca` | Database user |
| `DB_PASSWORD` | `ownca` | Database password |
| `DASHBOARD_ADMIN_USER` | `admin` | Default admin login |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Default admin password |
| `OWNCA_PROJECT_NAME` | `OwnCA` | Short brand name shown in header / sidebar |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Long title in topbar |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Filesystem path for CA / cert material |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Default key algorithm |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Default CA validity (days) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Default end-entity validity (days) |
| `OWNCA_CRL_DISTRIBUTION` | — | Public URL where CRLs are served (informational) |

## Supported algorithms

- **GOST R 34.10-2012** (256-bit, 512-bit) — keys, signatures
- **GOST R 34.11-2012** — hash functions
- **RSA** (2048, 4096) — fallback for environments without gost-engine
- **ECDSA** (P-256, P-384) and **Ed25519** — also supported

## Seeded certificate profiles

| Profile | Key Usage | Extended Key Usage |
|---|---|---|
| `server` | digitalSignature, keyEncipherment, keyAgreement | serverAuth |
| `client` | digitalSignature, keyEncipherment, dataEncipherment, keyAgreement | clientAuth |
| `server_client` | digitalSignature, keyEncipherment | serverAuth, clientAuth |
| `vpn` | digitalSignature | serverAuth, clientAuth |
| `user` | digitalSignature, keyEncipherment | clientAuth, emailProtection |
| `user_login` | digitalSignature, keyEncipherment | clientAuth + smartcard logon OID |
| `smartcard_logon` | digitalSignature | smartcard logon OID |
| `smime_sign` | digitalSignature, nonRepudiation | emailProtection |
| `code_signing` | digitalSignature | codeSigning |
| `timestamping` | digitalSignature | timeStamping (critical) |
