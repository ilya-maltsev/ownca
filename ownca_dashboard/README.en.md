# OwnCA Dashboard

[Русский](README.md) | **English**

---

The Django application behind the CA web panel. What the panel does from an
operator's point of view is in the root [README](../README.en.md); this file
covers the technical side: code layout, on-disk storage, environment variables.

## Layout

| Path | Contents |
|---|---|
| `config/` | Django settings, root `urls.py`, WSGI/ASGI |
| `dashboard/own_ca.py` | All crypto interaction: wrappers around `openssl` and the `ownca_capi` bridge, per-CA config generation, issuance, revocation, CRLs, PKCS#12, X.509 parsing |
| `dashboard/cryptopro.py` | CryptoPro provider status, licence, DRBG gamma |
| `dashboard/models.py` | `CertificateAuthority`, `Certificate`, `CertProfile`, the OID-field registry, system settings |
| `dashboard/views.py`, `urls.py` | Panel views and internal JSON endpoints |
| `dashboard/templates/`, `dashboard/static/` | Templates and static assets |
| `dashboard/webhelp/` | Help portal: `nav.py` + `content/{ru,en}/*.md`, markdown rendered on the fly |
| `dashboard/management/commands/` | `ensure_admin`, `cryptopro_setup`, `strip_cert_text` |
| `dashboard/tests/` | Tests (`manage.py test dashboard`) |
| `capi/` | Source of the CAPILite C bridge — see [capi/README.md](capi/README.md) |
| `locale/` | `ru` / `en` translations |

`own_ca.py` raises a single exception type, `OwnCAError`, so the view layer can
surface one comprehensible error regardless of what failed underneath.

## On-disk storage

The database holds only the metadata index used for filtering and listing; the
files under `OWNCA_STORAGE_DIR` are the source of truth. All paths are computed
from the model row (`.storage_dir`, `.cert_path`, `.key_path`, …).

```
cas/<uuid>/
    ca.crt                 CA certificate (PEM)
    ca.key                 openssl CA private key (PEM, 0600); absent for CryptoPro CAs
    backend                'openssl' or 'capilite:<container>' — fixed at creation
    subject_x500           the exact DN string used at creation (byte-stable chains)
    openssl.cnf            config for `openssl ca` operations
    index.txt[.attr]       openssl's issued-certificate database
    serial, crlnumber      counters (hex)
    crl_days               CRL validity
    crl.pem                latest generated CRL
    newcerts/<SERIAL>.pem  copies of signed certificates
certs/<uuid>/
    cert.pem               certificate
    key.pem                private key (0600) — only for server-side generation
    csr.pem                the request (always written)
crls/
    <ca_name>.crl          published copies, written by "Rebuild all CRLs"
```

The `backend` marker is the authoritative record of which backend signs for a
given CA; CAs predating CryptoPro support are treated as openssl. For a
CryptoPro CA the private key lives in a provider container
(`/var/opt/cprocsp/keys`), not here — which matters for backups.

## Architecture

```
Browser ──> nginx (GOST + RSA TLS) ──> Django
                                        |--> openssl (+ gost-engine)
                                        |--> ownca_capi ──> CryptoPro CSP  (optional)
                                        |--> OWNCA_STORAGE_DIR  (keys, certificates, CRLs)
                                        |--> PostgreSQL         (metadata index)
```

Actual ports and volumes depend on the environment — see [dev_env](../dev_env/)
and [demo](../demo/).

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `DJANGO_SECRET_KEY` | insecure dev key | Django signing key — must be your own outside a test rig |
| `DJANGO_DEBUG` | `True` | Debug mode |
| `DJANGO_ALLOWED_HOSTS` | `*` | Allowed hosts (comma-separated) |
| `CSRF_TRUSTED_ORIGINS` | `http://127.0.0.1:8000,http://localhost:8000` | CSRF trusted origins |
| `DJANGO_SECURE_COOKIES` | `True` | `Secure` flag on the session cookie; turn off only for HTTP access |
| `DJANGO_LOG_LEVEL` | `INFO` | Application log level |
| `DB_HOST` / `DB_PORT` | `127.0.0.1` / `5432` | PostgreSQL |
| `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `ownca` / `ownca` / `ownca` | Database parameters |
| `DASHBOARD_ADMIN_USER` | `admin` | Admin login (created by `ensure_admin`) |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Admin password |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Long title in the topbar |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | CA / certificate storage path |
| `OWNCA_OPENSSL_BIN` | `openssl` | Path to the openssl binary |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Default key algorithm |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Default CA validity (days) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Default end-entity validity (days) |
| `OWNCA_CRL_DISTRIBUTION` | — | Public URL where CRLs are served (informational) |
| `UPLOAD_MAX_MB` | `10` | Upload size limit |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Enable the CryptoPro backend (effective only when the build marker is present) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Licence serial; a serial set in the panel wins |
| `OWNCA_CRYPTOPRO_MARKER` | `/opt/ownca/.cryptopro_available` | Marker of a CryptoPro-enabled build |
| `OWNCA_CRYPTOPRO_ROOT` | `/opt/cprocsp` | CryptoPro install root |
| `OWNCA_CRYPTOPRO_GAMMA_DIR` | `/var/opt/cprocsp/dsrf` | DRBG gamma directory |
| `OWNCA_CRYPTOPRO_SHIM_BIN` | `/opt/ownca/bin/ownca_capi` | CAPILite bridge |

The marker and the bridge deliberately live **outside** `/opt/app`: the dev
stack bind-mounts the sources there and would shadow anything the image baked
in.

## Crypto backends

- **openssl (+ gost-engine)** — the default; RSA, ECDSA, Ed25519 and GOST R
  34.10-2012 (256 / 512) with GOST R 34.11-2012 and SHA-256 hashes. Keys live on
  disk as PEM.
- **CryptoPro CSP** — the optional certified backend for GOST; the key never
  leaves the provider container. Enabled at build and at runtime, and chosen per
  CA. Limitations are in the root
  [README](../README.en.md#cryptopro-backend-limitations); the bridge is
  documented in [capi/README.md](capi/README.md).

Under `manage.py test`, `OWNCA_CRYPTOPRO_ENABLED` is forced off: the suite
exercises the openssl backend and must behave identically on images with and
without CryptoPro. The CryptoPro tests flip the flag per case and stub the
bridge calls.

## Development

Tests, translations, webhelp work and `manage.py` commands all run inside the
dev stack container — see [dev_env/README.en.md](../dev_env/README.en.md).
