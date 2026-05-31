# OwnCA — Dev Environment

[Русский](README.md) | **English**

---

Docker environment for local development. Images are built from source; the
panel code is mounted into the container for live-reload.

## Layout

| File | Purpose |
|---|---|
| `docker-compose.yml` | Definition of three services (PostgreSQL, ownca-gh-dev-nginx, ownca-gh-dev-dashboard) |
| `init-db.sh` | Database initialization on first PostgreSQL start (creates user/schema) |
| `postgresql.conf`, `pg_hba.conf` | PostgreSQL configuration for the dev stack |
| `dashboard/Dockerfile` | Builds the Django + openssl/gost-engine image |
| `dashboard/entrypoint.sh` | Dashboard startup sequence (see below) |
| `nginx/Dockerfile` | Builds nginx with GOST TLS support |
| `nginx/entrypoint.sh` | Generates GOST + RSA PKI for nginx itself |
| `nginx/nginx.conf` | TLS frontend, proxies to dashboard:8001 |
| `nginx/openssl-gost.cnf` | OpenSSL configuration with gost-engine enabled |

## Quick start

```bash
cd dev_env
docker compose up -d --build
```

A single `docker-compose.yml` brings up all three services. On first start
it automatically:
- creates the `ownca` database,
- generates GOST + RSA certificates for nginx,
- applies Django migrations,
- creates the admin user.

The panel is reachable at:
- `https://127.0.0.1:8444` — through nginx (GOST + RSA TLS, full-stack check),
- `http://127.0.0.1:8001` — directly to Django (for debugging).

Default login: `admin` / `admin`.

## Live-reload

The `ownca_dashboard/` directory is mounted into `/opt/app` of the
container — changes to Python code, templates, and static files are picked
up by the Django StatReloader without rebuilding. A rebuild is only needed
when `requirements.txt` or `Dockerfile` changes.

## Dashboard startup sequence

On every container start, `dashboard/entrypoint.sh` runs:

1. `python manage.py compilemessages` — recompile `.po` → `.mo`
   (translation edits are picked up without a manual command).
2. `python manage.py collectstatic --noinput` — refresh `staticfiles/`.
3. `python manage.py migrate --noinput` — apply migrations.
4. `python manage.py ensure_admin` — create/update the admin user from
   environment variables.
5. `exec python manage.py runserver $BIND_ADDRESS` — start the dev server
   with autoreload.

## Nginx startup sequence

On first start, `nginx/entrypoint.sh` generates and persists into the
`certs` volume:

| Certificate | Purpose |
|---|---|
| `ca.crt` / `ca.key` | GOST CA for nginx (internal, separate from the one OwnCA issues) |
| `nginx.crt` / `nginx.key` | GOST TLS server certificate (`gost2012_256`, paramset A) |
| `ca-rsa.crt` / `ca-rsa.key` | RSA CA for nginx |
| `nginx-rsa.crt` / `nginx-rsa.key` | RSA TLS server certificate for standard browsers |

On subsequent starts, if `ca.crt` already exists in the volume, generation
is skipped. Extra SANs are passed via `CERT_EXTRA_SANS`; validity via
`CERT_DAYS`.

## Ports

| Port | Service | Protocol |
|---|---|---|
| `8001` | Dashboard | HTTP (published to host — for debugging) |
| `8444` | nginx → dashboard | GOST + RSA TLS |

PostgreSQL is not published to the host — it is reachable only from the
`devnet` docker network.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Admin login |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Admin password |
| `DB_HOST` | `ownca-gh-dev-postgresql` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `ownca` | Database name |
| `DB_USER` | `ownca` | Database user |
| `DB_PASSWORD` | `ownca` | Database password |
| `DJANGO_DEBUG` | `True` | Django mode (enabled in dev) |
| `DJANGO_ALLOWED_HOSTS` | `*` | Allowed hosts |
| `CSRF_TRUSTED_ORIGINS` | list from compose | CSRF trusted origins |
| `OWNCA_PROJECT_NAME` | `OwnCA` | Brand shown in header / sidebar |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Long title in topbar |
| `OWNCA_STORAGE_DIR` | `/var/lib/ownca` | Filesystem path for CA / cert material |
| `OWNCA_DEFAULT_KEY_ALG` | `gost2012_256` | Default key algorithm |
| `OWNCA_DEFAULT_CA_DAYS` | `3650` | Default CA validity (days) |
| `OWNCA_DEFAULT_CERT_DAYS` | `365` | Default end-entity validity (days) |
| `OWNCA_CRL_DISTRIBUTION` | — | Public URL where CRLs are served (informational) |
| `BIND_ADDRESS` | `0.0.0.0:8001` | runserver bind address inside the container |

For the nginx container additionally:

| Variable | Default | Description |
|---|---|---|
| `CERT_DAYS` | `365` | Validity of nginx-issued certificates |
| `CERT_EXTRA_SANS` | — | Extra SANs (format: `DNS:foo,IP:1.2.3.4`) |

## Common operations

All commands run inside the container so the host stays untouched.

### Tests

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py test dashboard -v2
```

The Django test runner creates a separate database on the same PostgreSQL,
so the DB user needs the `CREATEDB` privilege (one-time):

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-postgresql \
    psql -U postgres -c "ALTER USER ownca CREATEDB;"
```

### Django shell / management commands

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py shell
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py makemigrations
```

### PostgreSQL

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-postgresql \
    psql -U ownca -d ownca
```

### Translations (i18n)

After editing strings in code/templates:

```bash
docker compose -f dev_env/docker-compose.yml exec ownca-gh-dev-dashboard \
    python manage.py makemessages -l ru -l en
```

The resulting `.po` files are translated; restarting the container (or a
manual `compilemessages`) updates `.mo`. Compile runs automatically on
every start — no separate step needed.

### Webhelp (contextual help)

Help content lives in `ownca_dashboard/dashboard/webhelp/content/{ru,en}/*.md`
and is rendered on the fly. Rendering is wrapped in `lru_cache`, so edits to
`.md` files are **not** picked up by Django's autoreloader — restart the
container to flush the cache:

```bash
docker compose -f dev_env/docker-compose.yml restart ownca-gh-dev-dashboard
```

Changes to the navigation (`webhelp/nav.py`) and to `.py` modules are
picked up by the reloader as usual.

### Logs

```bash
docker compose -f dev_env/docker-compose.yml logs -f ownca-gh-dev-dashboard
docker compose -f dev_env/docker-compose.yml logs -f ownca-gh-dev-nginx
docker compose -f dev_env/docker-compose.yml logs -f ownca-gh-dev-postgresql
```

## Resetting the environment

Stop while keeping data:

```bash
docker compose -f dev_env/docker-compose.yml down
```

Full cleanup (database, generated nginx certificates, CA material):

```bash
docker compose -f dev_env/docker-compose.yml down -v
```

Volumes:
- `pg_data` — PostgreSQL data,
- `certs` — GOST/RSA nginx certificates,
- `ownca_data` — `/var/lib/ownca` (CA, keys, issued certificates, CRL).

## Dev stack architecture

```
Browser ──> ownca-gh-dev-nginx :8444 ──> ownca-gh-dev-dashboard :8001 ──> ownca-gh-dev-postgresql :5432
                  ^                       |                       (devnet)
                  |                       |
            volume: certs           volume: ownca_data
            (GOST + RSA              (CA, keys, CRL)
             TLS frontend)
```

All services are isolated in the `devnet` bridge network; only `8444` and
`8001` are published to the host.
