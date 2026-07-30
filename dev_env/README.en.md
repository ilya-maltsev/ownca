# OwnCA — Dev Environment

[Русский](README.md) | **English**

---

Docker environment for local development: images are built from source and the
panel code is mounted into the container for live-reload. The product itself is
described in the root [README](../README.en.md).

## Quick start

```bash
cd dev_env
docker compose up -d --build
```

The panel is reachable at:

| Address | What it is |
|---|---|
| `https://127.0.0.1:8444` | through nginx (GOST + RSA TLS) — full-stack check |
| `http://127.0.0.1:8001` | straight to Django — for debugging |

Default login: `admin` / `admin`. PostgreSQL is not published to the host — it
is reachable only inside the `gh_ownca_devnet` network.

On first start the `ownca` database is created, GOST + RSA certificates are
generated for nginx, Django migrations are applied and the admin user is
created — all automatically.

## Layout

| File | Purpose |
|---|---|
| `docker-compose.yml` | Three services: `gh_ownca_dev_postgresql`, `gh_ownca_dev_nginx`, `gh_ownca_dev_dashboard` |
| `build.sh` | Builds the images, optionally baking in CryptoPro CSP |
| `init-db.sh` | Database initialization on first PostgreSQL start |
| `postgresql.conf`, `pg_hba.conf` | PostgreSQL configuration |
| `dashboard/Dockerfile` | Django + openssl/gost-engine image (+ CryptoPro CSP when the distribution is staged) |
| `dashboard/entrypoint.sh` | Dashboard startup sequence |
| `dashboard/vendor/` | Staging dir for the CryptoPro distribution during a build (filled by `build.sh`) |
| `nginx/Dockerfile`, `nginx/entrypoint.sh` | nginx with GOST TLS, generating its own PKI |
| `nginx/nginx.conf` | TLS frontend, proxies to `dashboard:8001` |
| `nginx/openssl-gost.cnf` | OpenSSL configuration with gost-engine enabled |

Every object in the stack is namespaced under `gh_ownca` (project, containers,
network, volumes) so it can never collide with another `dev_env/` stack on the
same host: without an explicit `name:` Compose would derive the project name
from the directory (`dev_env`) and two such stacks would silently share the
same volumes.

## Live-reload

`ownca_dashboard/` is mounted at `/opt/app`: Python code, templates and static
files are picked up by Django's StatReloader without a rebuild. A rebuild is
needed only when `requirements.txt` or the `Dockerfile` changes.

The exception is the C bridge `ownca_dashboard/capi/ownca_capi.c` — compiled
code, rebuilt together with the image. The fast-iteration trick is in
[capi/README.md](../ownca_dashboard/capi/README.md).

## Startup sequences

`dashboard/entrypoint.sh` on every start: `compilemessages` (translation edits
are picked up without a manual command) → `collectstatic` → `migrate` →
`ensure_admin` → `cryptopro_setup` (a no-op without CryptoPro) → `runserver
$BIND_ADDRESS`.

`nginx/entrypoint.sh` generates its own PKI into the `certs` volume on first
start — a GOST CA and server certificate (`gost2012_256`, paramset A) plus an
RSA pair for standard browsers. This is **nginx's own** PKI and has nothing to
do with the CAs OwnCA issues. On subsequent starts generation is skipped if
`ca.crt` is already in the volume. Extra SANs via `CERT_EXTRA_SANS`, validity
via `CERT_DAYS`.

## Where things live

| Path in the container | Contents | Volume |
|---|---|---|
| `/var/lib/ownca` | CA certificates, issued certificates, CSRs, CRLs, counters, backend markers; private keys of **openssl**-backed CAs (PEM, `0600`) | `gh_ownca_data` |
| `/var/lib/ownca/crls` | Published CRLs — a separate bind mount so they can be served | directory `dev_env/crls/` |
| `/var/opt/cprocsp/keys` | CryptoPro containers holding the private keys of GOST CAs and certificates | `gh_ownca_cryptopro_keys` |
| `/var/opt/cprocsp/dsrf` | DRBG gamma pools (`db1/kis_1`, `db2/kis_1`) | `gh_ownca_cryptopro_gamma` |
| `/etc/nginx/certs` | nginx's own PKI | `gh_ownca_certs` |
| `/var/lib/postgresql/data` | Metadata index | `gh_ownca_pg_data` |
| `/opt/cprocsp`, `/opt/ownca/bin/ownca_capi` | CryptoPro distribution and the CAPILite bridge | in the image |

The gamma pool has its own volume deliberately: it is consumed (36 bytes per key
generation) and must survive restarts, otherwise key generation would fail after
every restart until gamma is re-uploaded.

> **Backups.** For a CryptoPro-backed CA the private key is **not** under
> `/var/lib/ownca` — it lives in a container under `/var/opt/cprocsp/keys`.
> Backing up the storage directory alone preserves the certificates and the
> index but not the keys: the restored CA will not be able to sign anything.
> Back up both volumes, and do it consistently.

## Environment variables

Set them in `dev_env/.env` — docker compose picks it up automatically.

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Admin login |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Admin password |
| `DB_HOST` | `gh_ownca_dev_postgresql` | PostgreSQL host |
| `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `5432` / `ownca` / `ownca` / `ownca` | Database parameters |
| `DJANGO_DEBUG` | `True` | Django mode |
| `DJANGO_ALLOWED_HOSTS` | `*` | Allowed hosts |
| `CSRF_TRUSTED_ORIGINS` | list from compose | CSRF trusted origins |
| `DJANGO_SECURE_COOKIES` | `False` in the dev stack (`True` in the app) | `Secure` flag on the session cookie; off in dev so `http://…:8001` keeps working |
| `DJANGO_SECRET_KEY` | insecure dev key | Django signing key |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Title in the topbar |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | CA / certificate storage path |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Default key algorithm |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Default CA validity (days) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Default end-entity validity (days) |
| `OWNCA_CRL_DISTRIBUTION` | — | Public URL where CRLs are served (informational) |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Enable the CryptoPro backend at start-up (effective only when it is baked into the image) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Licence serial (empty → 90-day demo; a serial set in the panel wins) |
| `OWNCA_CRYPTOPRO_GAMMA_DIR` | `/var/opt/cprocsp/dsrf` | DRBG gamma directory |
| `OWNCA_CRYPTOPRO_ROOT` | `/opt/cprocsp` | CryptoPro install root |
| `OWNCA_CRYPTOPRO_SHIM_BIN` | `/opt/ownca/bin/ownca_capi` | CAPILite bridge |
| `OWNCA_CRYPTOPRO_MARKER` | `/opt/ownca/.cryptopro_available` | Marker of a CryptoPro-enabled build |
| `UPLOAD_MAX_MB` | `10` | Upload size limit |
| `BIND_ADDRESS` | `0.0.0.0:8001` | runserver bind address inside the container |

Build time (`build.sh`, not the container):

| Variable | Default | Description |
|---|---|---|
| `OWNCA_CRYPTOPRO_DIST` | `dev_env/cryptopro_linux-amd64_deb.tgz` | Path to the CryptoPro distribution (`.tgz` with `.deb` packages); `none` forces a build WITHOUT CryptoPro |

For the nginx container: `CERT_DAYS` (default `365`) and `CERT_EXTRA_SANS`
(format `DNS:foo,IP:1.2.3.4`).

## Common operations

Everything runs inside the containers so the host stays untouched.

```bash
D='docker compose -f dev_env/docker-compose.yml exec'

# tests (needs the CREATEDB privilege once — see below)
$D gh_ownca_dev_dashboard python manage.py test dashboard -v2

# shell and management commands
$D gh_ownca_dev_dashboard python manage.py shell
$D gh_ownca_dev_dashboard python manage.py makemigrations

# PostgreSQL
$D gh_ownca_dev_postgresql psql -U ownca -d ownca

# translations, after editing strings in code/templates
$D gh_ownca_dev_dashboard python manage.py makemessages -l ru -l en

# logs
docker compose -f dev_env/docker-compose.yml logs -f gh_ownca_dev_dashboard
```

The Django test runner creates a separate database on the same PostgreSQL, so
the DB user needs the `CREATEDB` privilege (one-time):

```bash
docker compose -f dev_env/docker-compose.yml exec gh_ownca_dev_postgresql \
    psql -U postgres -c "ALTER USER ownca CREATEDB;"
```

The resulting `.po` files are translated by hand; `compilemessages` runs on
every container start, so no separate step is needed.

**Webhelp.** Help content lives in
`ownca_dashboard/dashboard/webhelp/content/{ru,en}/*.md` and is rendered on the
fly, but rendering is wrapped in `lru_cache` — the reloader does **not** pick up
`.md` edits, so run `docker compose … restart gh_ownca_dev_dashboard`. Changes
to `webhelp/nav.py` and other `.py` modules are picked up as usual.

## Resetting the environment

```bash
docker compose -f dev_env/docker-compose.yml down      # stop, data kept
docker compose -f dev_env/docker-compose.yml down -v   # full cleanup
```

> `down -v` also destroys the CryptoPro key containers along with the gamma —
> the keys of every CryptoPro-backed CA are lost irrecoverably.

## CryptoPro CSP backend (optional)

The CryptoPro distribution (a `.tgz` with `.deb` packages) is not part of the
repository. Enablement is two-level — build and runtime:

```bash
# put cryptopro_linux-amd64_deb.tgz into dev_env/ and:
dev_env/build.sh
# or point at the distribution explicitly:
OWNCA_CRYPTOPRO_DIST=/path/to/cryptopro_linux-amd64_deb.tgz dev_env/build.sh

# then enable the backend at runtime:
echo 'OWNCA_CRYPTOPRO_ENABLED=True' >> dev_env/.env
cd dev_env && docker compose up -d
```

`build.sh` copies the distribution to `dashboard/vendor/cryptopro.tgz`, runs
`docker compose build`, and removes the copy from the context. The Dockerfile
installs the packages (the version is derived from the package filename inside
the archive), compiles `ownca_dashboard/capi/ownca_capi.c` →
`/opt/ownca/bin/ownca_capi`, and writes the `/opt/ownca/.cryptopro_available`
marker. Without the distribution the image builds without CryptoPro (with an
explicit message), and `OWNCA_CRYPTOPRO_ENABLED` is inert in such an image.

The provider is managed on the **Maintenance** page: status, licence, remaining
DRBG gamma and gamma upload. Gamma is mandatory for key generation on a headless
box — without it generation fails with `NTE_SILENT_CONTEXT (0x80090022)`: the
CSP tries to ask for entropy through a dialog while the context was acquired
with `CRYPT_SILENT`. Test gamma can be generated there too — test rigs only.

Backend limitations are in the root
[README](../README.en.md#cryptopro-backend-limitations); the bridge's internals
are in [capi/README.md](../ownca_dashboard/capi/README.md).

## Stack architecture

```
Browser ──> gh_ownca_dev_nginx :8444 ──> gh_ownca_dev_dashboard :8001 ──> gh_ownca_dev_postgresql :5432
                  ^                       |                    (gh_ownca_devnet)
                  |                       |
          volume: certs            volume: ownca_data
          (GOST + RSA TLS)         (CAs, keys, CRLs)
```

All services are isolated in the `gh_ownca_devnet` bridge network; only `8444`
and `8001` are published to the host.
