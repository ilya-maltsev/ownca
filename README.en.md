# OwnCA

[Русский](README.md) | **English**

---

Self-hosted web panel for a Certificate Authority — a replacement for the pile
of EasyRSA and `openssl ca` shell scripts. It does the same job: stands up
roots and intermediates, issues and revokes X.509 certificates, keeps CRLs
fresh, exports keys and certificates in PEM and PKCS#12 — only from a browser
instead of a terminal.

It runs on stock OpenSSL with RSA, ECDSA and Ed25519. GOST R 34.10-2012 support
is strictly opt-in: with GOST switched off you get an ordinary CA on an
unpatched OpenSSL with no engine to install. Where certified cryptography is
required, the GOST path can be moved onto CryptoPro CSP.

## Live demo

### https://ilya-maltsev.github.io/ownca/en/dashboard.html

## What it does

- **Certificate authorities.** Roots and intermediates: key and self-signed
  certificate generation, signing an intermediate with its parent, and importing
  an existing CA (a certificate with its private key, or a PKCS#12/PFX
  container) to keep signing with it. You choose the key algorithm, Subject DN,
  validity period and path length (`pathlen`). An intermediate is created in
  its parent's key family — GOST and RSA never mix within one chain.
- **Certificate issuance.** The key is either generated server-side or arrives
  with an external PKCS#10 request — in the latter case the certificate's
  contents and its key family are taken from the request itself, not from the
  form fields. A CA only signs certificates of its own key family
  (`gost` / `rsa` / `ec` / `ed25519`); incompatible combinations are rejected
  before issuance. GOST keys get a selectable parameter set.
- **Extension profiles.** Ten seeded ones (`server`, `client`, `server_client`,
  `vpn`, `user`, `user_login`, `smartcard_logon`, `smime_sign`, `code_signing`,
  `timestamping`) plus any of your own: KU and EKU, basicConstraints, name and
  policy constraints, distribution-point overrides, and bound OID fields from
  the registry (DNS, IP, Email, URI, UPN, SNILS, INN, OGRN, OGRNIP and others).
  Without a profile there is a free-form mode with arbitrary extensions.
- **Distribution points.** CRL, AIA (caIssuers and OCSP), SIA, freshestCRL and
  issuerAltName are set per CA and can be overridden by a profile.
- **Revocation and CRLs.** The revocation reason reaches the CRL as
  `reasonCode`. The list is reissued automatically on every revocation, manually
  on demand, and for every enabled CA at once into the distribution directory.
- **Renewal** of a certificate under a new validity period and serial number
  from the same request and the same key; the original is left untouched.
- **Export.** The certificate (`.crt`), private key, request (`.csr`), a PEM
  file holding certificate + key + chain, PKCS#12, plus the CA certificate and
  its CRL. A CA container is encrypted with standard AES or a GOST suite
  (Kuznyechik and Magma per TK-26, or legacy GOST 28147-89). GOST keys also
  offer the TK-26 format (`.gost.p12`) — a PFX per RFC 9337 and RFC 9548 with
  Kuznyechik or Magma as the cipher.
- **Issuance modes.** Server-side key generation and individual algorithm
  families can be disabled — the corresponding options then disappear from the
  forms and are rejected server-side.
- **Maintenance.** openssl version, gost-engine status, metadata reindex from
  disk, rebuild of every CRL; on a build with CryptoPro — provider status,
  licence and DRBG gamma.
- **Two languages** — Russian (default) and English.

Working with the interface is covered by the built-in contextual help, opened
straight from the panel and always matching the current page. To see the panel
without installing anything, use the [live demo](#live-demo).

## Certificate profiles

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

## Supported algorithms

Standard algorithms work on stock OpenSSL out of the box. GOST requires
gost-engine and can be switched off, leaving a clean RSA / ECDSA / Ed25519 CA.

- Digital signature: RSA (2048 / 4096), ECDSA (P-256, P-384), Ed25519;
  GOST R 34.10-2012 (256 / 512 bit) — optional.
- Hash functions: SHA-256; GOST R 34.11-2012 — optional.
- Frontend TLS: ordinary RSA/ECDHE suites, plus
  GOST2012-KUZNYECHIK-KUZNYECHIKOMAC and GOST2012-MAGMA-MAGMAOMAC when GOST is
  enabled.

## CryptoPro CSP backend (optional, certified GOST)

The CA's GOST operations can run on the certified **CryptoPro CSP** instead of
the free `openssl + gost-engine`. The private key is then born and stays inside
a provider container: key generation, root self-signing, intermediate CA
signing, end-entity issuance (both server-side key generation and external
CSRs), renewal, CRL generation, PKCS#12 export and import of an existing GOST
CA from PKCS#12/PFX all go through CryptoPro. Non-GOST algorithms always stay
on openssl.

Enablement is two-level: the CryptoPro distribution must be staged **into the
image build** (it is not part of this repository), and the backend is then
switched on **at container start** through an environment variable. The build
commands live in [dev_env/README.en.md](dev_env/README.en.md) and
[demo/README.en.md](demo/README.en.md).

The backend is chosen **per CA, not per installation**: it is fixed at creation
time and never changes afterwards. openssl-backed and CryptoPro-backed CAs
therefore coexist in one deployment; pre-existing CAs stay on openssl, and an
intermediate inherits its parent's backend.

On a headless server the provider needs **DRBG gamma** — external entropy that
is consumed on every key generation. You upload it on the Maintenance page,
which also shows the remaining amount and manages the licence (without a serial
of your own, CryptoPro runs on its built-in 90-day demo licence). Test gamma can
be generated right there, but **for a test rig only** — certified operation
requires a hardware source.

### CryptoPro backend limitations

The limitations apply only to GOST CAs created while CryptoPro was enabled. None
of them is silent: anything unsupported is either hidden in the UI, flagged up
front, or refused with an explicit error before the operation starts.

**1. The private key is non-exportable** — that is the whole point of the
certified backend. So there is no PEM key download, no "certificate + key +
chain" PEM bundle, and no PEM-pair import of a GOST CA (use PKCS#12/PFX — the
key then lands straight in a container). PKCS#12 export still works.

**2. PKCS#12 format — CryptoPro's own only.** The resulting PFX imports
correctly into CryptoPro itself, but TK-26 (`.gost.p12`) and the GOST container
encryption suites cannot be selected: the platform exposes no control over that
parameter. The panel does not offer those options for a CryptoPro CA, and no
format is substituted behind your back.

**3. The set of X.509 extensions is closed.**

| Supported | Not supported — issuance refuses |
|---|---|
| `basicConstraints` (+ pathlen), `keyUsage`, `extendedKeyUsage` (names and raw OIDs), critical flags | `nameConstraints` |
| `subjectKeyIdentifier`, `authorityKeyIdentifier` (incl. `issuer:always`) | `policyConstraints`, `inhibitAnyPolicy`, `certificatePolicies` |
| `subjectAltName`: DNS, IP, email, URI | `otherName` SAN entries |
| `crlDistributionPoints`, `authorityInfoAccess` (caIssuers + OCSP) | free-form "Extra extensions" lines |
| `subjectInfoAccess` (caRepository), `freshestCRL` | OID-registry fields placed as "Extension" |
| `issuerAltName`: DNS, IP, email, URI | `issuerAltName` of type `dirName`, `otherName`, `RID` |

A profile carrying anything from the right-hand column is flagged in the profile
editor and in the issue form, so the incompatibility shows up before the form is
filled in rather than on submit.

Everything else is on par with openssl: GOST parameter sets, `csr.pem` for
server-side key generation, `reasonCode` in the CRL, CRL validity, and the
profile's SKI/AKI toggles.

## Limitations and scope

- **A single administrator account**, provisioned from environment variables.
  There are no roles, no permission separation, and no per-user audit trail.
- **Web UI only.** No automation protocols (ACME, SCEP, EST, CMP) and no
  external issuance API.
- **No OCSP responder.** The AIA/OCSP fields merely write a URL into the
  certificate; something else has to answer on it. Revocation checking is via
  CRL.
- **CRLs are refreshed on events, not on a schedule** — on revocation and on
  demand. There is no scheduler and no expiry notifications; the dashboard only
  lists certificates that are about to expire.
- **No hardware tokens or HSMs (PKCS#11).** The only certified key storage
  option is the software CryptoPro CSP container.
- **Storage is a local directory** of a single instance. Clustering and
  replication are out of scope; PostgreSQL holds only the metadata index, while
  the files on disk are the source of truth.
- **The environments shipped here are test rigs.** The panel runs on Django's
  development server with a self-signed TLS certificate and the default `admin`
  password. Production use needs a proper WSGI server, your own
  `DJANGO_SECRET_KEY`, real frontend certificates, and changed credentials.
- **Backups.** For an openssl-backed CA the keys sit in the storage directory
  next to the certificates; for a CryptoPro-backed CA they live separately, in
  provider containers. Both volumes must be backed up, and consistently: a
  CryptoPro CA restored from the storage directory alone will not be able to
  sign anything. The exact volume list is in the environment READMEs.
- **GOST on gost-engine is a free, uncertified implementation.** If certified
  cryptography is required, the CryptoPro CSP backend is the answer — with the
  limitations described above.

## Running

Two ready-to-use Docker Compose scenarios:

- **[dev_env/](dev_env/)** — built from source, code mounted into the
  container, live-reload. For development and debugging. See
  [dev_env/README.en.md](dev_env/README.en.md).
- **[demo/](demo/)** — pre-built images; the stack moves to an air-gapped host
  as a single archive. See [demo/README.en.md](demo/README.en.md).

## Repository layout

| Component | Description |
|---|---|
| [ownca_dashboard](ownca_dashboard/) | CA web panel (Django) — [README](ownca_dashboard/README.en.md) |
| [dev_env](dev_env/) | Docker Compose for development — [README](dev_env/README.en.md) |
| [demo](demo/) | Docker Compose for demos and transfer — [README](demo/README.en.md) |

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
