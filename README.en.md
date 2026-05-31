# OwnCA

[Русский](README.md) | **English**

---

Self-hosted web panel for a Certificate Authority — an EasyRSA replacement
with a UI. It does what your pile of EasyRSA shell scripts does — stand up
roots and intermediates, issue and revoke X.509 certificates, keep CRLs
fresh, export keys and certificates in PEM and PKCS#12 — only from a browser
instead of a terminal.

It runs on stock OpenSSL with RSA, ECDSA and Ed25519; GOST R 34.10-2012
support is strictly opt-in. With GOST switched off you're on a clean,
unpatched OpenSSL build with no engine to install.

## Components

| Component | Description |
|---|---|
| [ownca_dashboard](ownca_dashboard/) | CA web panel (Django) |
| [dev_env](dev_env/) | Docker Compose for dev environment (live-reload). See [dev_env/README.en.md](dev_env/README.en.md) |
| [demo](demo/) | Docker Compose for demo environment (pre-built images). See [demo/README.en.md](demo/README.en.md) |

## Architecture

```
Browser ──────> nginx (RSA/ECDSA TLS · GOST optional)
                       |
              Dashboard
                  |--> /var/lib/ownca
                  |       (CA, issued certificates, CRL)
                  |--> PostgreSQL
                          (metadata index)
```

CA state (issued certificate database, serial numbers, CRL) is stored as
files under `OWNCA_STORAGE_DIR/`. PostgreSQL holds only the metadata index
for fast filtering and listing.

## Web panel

Sidebar:

| Section | Sidebar items |
|---|---|
| **Monitor** | Dashboard |
| **Certificate Operations** | Certificates, Cert Issue |
| **Certification Authority** | Authorities, Cert Profiles |
| **System** | Configuration, Maintenance |

Capabilities:

- **Authorities** (`/cas/`) — create root and intermediate CAs, choose
  key algorithm, Subject DN, validity period. The CA detail page exposes
  **Distribution points** fields (CRL/AIA/OCSP/SIA/freshestCRL/issuerAltName).
- **Certificates** (`/certificates/`) — list of issued certificates filtered
  by CA and status (active / revoked / expired); X.509 detail view; download
  `.crt`, `.key`, `.csr`, PEM bundle, and `.p12`. For GOST keys an
  additional **TK-26 compatible format** export (`.gost.p12`) is
  offered — a PFX conformant to RFC 9337 + RFC 9548: the key bag and
  cert envelope are wrapped with PBES2 / PBKDF2-HMAC-Streebog over
  Kuznyechik- or Magma-CTR-ACPKM (cipher picked in the export form);
  the outer MAC is HMAC-Streebog-512 with the RFC 9548 §3 KDF. Built
  with stock `openssl pkcs12 -export` against gost-engine
  ([`gost-engine/engine`](https://github.com/gost-engine/engine),
  branch `master`; RFC 9337 / RFC 9548 support merged upstream in PR #527).
- **Cert Issue** (`/custom-cert-issue/`) — unified issuance form: pick a
  CA, an optional profile, fill in Subject DN and SAN.
  CSR import or server-side key generation are both supported. For GOST
  keys, paramset selection is available. A CA can only sign certificates
  whose key belongs to the same family (`gost` / `rsa` / `ec` / `ed25519`);
  the form's algorithm dropdown filters to the chosen CA's family, and
  the backend additionally rejects incompatible submissions.
- **Cert Profiles** (`/cert-profiles/`) — registry of extension profiles
  (`server`, `client`, `code_signing`, `user`, `smartcard_logon`,
  `user_login`, `smime_sign`, `timestamping`, `vpn`, `server_client`).
  Edit KU/EKU, name/policy constraints, distribution-point overrides, and
  bind **OID fields**. The **Copy** button clones a profile.
- **Configuration** (`/system/configuration/`) — issuance mode toggles and
  environment-variable overview.
- **Maintenance** (`/system/maintenance/`) — openssl version, gost-engine
  status, **Refresh metadata** button.
- **Webhelp** (`/webhelp/`) — bilingual contextual help portal; the
  **Help** button in the sidebar opens the page matching the current UI
  section.
- **Localization** — Russian (default) and English, switchable in the
  sidebar.

## Live Demo

### https://ilya-maltsev.github.io/ownca/en/dashboard.html

## Supported algorithms

Standard algorithms work on stock OpenSSL out of the box. GOST requires the
gost-engine and can be disabled, leaving a clean RSA/ECDSA/Ed25519 CA.

- Digital signature: RSA (2048 / 4096), ECDSA (P-256, P-384), Ed25519;
  GOST R 34.10-2012 (256 / 512 bit) — optional.
- Hash functions: SHA-256; GOST R 34.11-2012 — optional.
- TLS (nginx): RSA/ECDHE suites out of the box;
  GOST2012-KUZNYECHIK-KUZNYECHIKOMAC, GOST2012-MAGMA-MAGMAOMAC when GOST
  is enabled.

## Certificate profiles

Profiles define extensions, KU, EKU, and the set of OID fields populated at
issuance time. Default profiles:

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

Profiles are edited at `/cert-profiles/`. Each profile can be bound to a
set of OID fields from the registry (DNS Names, IP Addresses, Email, URI,
UPN, SNILS, INN, OGRN, OGRNIP, etc.) — values are entered on the issuance
form.

## Running

Two ready-to-use Docker Compose scenarios:

- **[dev_env/](dev_env/)** — live-reload, sources mounted into the
  container. Suitable for development and debugging. Details and commands
  in [dev_env/README.en.md](dev_env/README.en.md).
- **[demo/](demo/)** — pre-built images, can be transferred to an
  air-gapped host as a single archive. Details and image build in
  [demo/README.en.md](demo/README.en.md).
