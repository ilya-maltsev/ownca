# OwnCA — Demo Environment

[Русский](README.md) | **English**

---

Ready-to-run environment for demonstration. All services start with a single
command from pre-built images.

## Use cases

1. **Local build and run** — build images on the current machine and bring
   the stack up.
2. **Transfer to an air-gapped host** — build images once, pack them with
   deploy files into a single tar.gz, copy to a server without internet
   access, and deploy there.

Both flows are served by a single script — `build-images.sh`.

---

## 1. Local build and run

### Build images

```bash
cd demo
bash build-images.sh            # = bash build-images.sh build
```

What happens:

- `docker pull postgres:16` — official PostgreSQL image is pulled.
- `docker build -t ownca-nginx:latest` — nginx with GOST TLS support is
  built (`dev_env/nginx/Dockerfile`).
- `docker build -t ownca-dashboard:latest` — Django app with
  openssl/gost-engine is built (`dev_env/dashboard/Dockerfile`).

The build context is assembled from a whitelist (`DASHBOARD_FILES`,
`NGINX_FILES` in the script). Anything not listed (docs, `.git`, dev
tooling, runtime data) stays out of the image.

#### Build individual images

```bash
bash build-images.sh build dashboard      # only ownca-dashboard
bash build-images.sh build nginx          # only ownca-nginx
bash build-images.sh build postgres       # pull postgres:16 only
bash build-images.sh build dash nginx     # several at once
```

Short names: `dashboard` (`dash`), `nginx`, `postgres` (`pg`).

### Run

```bash
docker compose up -d
```

First start takes ~30 seconds:

- **PostgreSQL**: DB initialization, `ownca` user creation.
- **Nginx**: GOST + RSA PKI generation (CA and server certificates) —
  entrypoint `dev_env/nginx/entrypoint.sh`.
- **Dashboard**: `compilemessages` + `collectstatic` + `migrate` +
  `ensure_admin` — entrypoint `dev_env/dashboard/entrypoint.sh`.

### Access

| URL | Description |
|---|---|
| `https://localhost:9443` | Control panel (through nginx, GOST + RSA TLS) |

Login: `admin` / `admin` (configurable via `.env`).

---

## 2. Transfer to an air-gapped host

### On the build machine: export

```bash
cd demo
bash build-images.sh all                  # build + export
# or in two steps:
bash build-images.sh build
bash build-images.sh export
```

Result — a single file `demo/ownca-images.tar.gz` containing:

- `docker-images.tar` — `docker save` for all images (`ownca-nginx`,
  `ownca-dashboard`, `postgres:16`).
- Deploy files (`DEPLOY_PATHS` in the script): `build-images.sh`,
  `docker-compose.yml`, `init-db.sh`, `nginx.conf`, `README.md`,
  `README.en.md`.

Only what is needed for deployment ends up in the archive — sources, `.git`,
dev environment stay on the build machine.

#### Export individual images

```bash
bash build-images.sh export dashboard     # ownca-dashboard + deploy files only
bash build-images.sh export nginx pg      # nginx + postgres + deploy files
bash build-images.sh all dashboard        # build + export dashboard only
```

### On the target host: import and run

```bash
# 1. Extract the archive (e.g. into /opt)
tar xzf ownca-images.tar.gz -C /opt/
cd /opt/demo

# 2. Load images into the local Docker
bash build-images.sh import
# or selectively:
bash build-images.sh import dashboard

# 3. Bring the stack up
docker compose up -d
```

`import` extracts images from `docker-images.tar` via `docker load` and
removes the temporary tar after loading.

---

## Usage

After logging into the panel:

1. **Create a root Certificate Authority** on the **Authorities** page:
   set the name, Common Name, algorithm (default `gost2012_256`) and
   validity period.
2. **Issue a certificate** on the **Cert Issue** page: choose a CA, a
   profile (server / client / code-signing / user), Common Name, Subject
   DN, and SAN.
3. **Download** the certificate, key, and CSR from the certificate detail
   page.
4. If needed, **revoke** a certificate — the CRL is regenerated
   automatically.
5. **CRL** is downloadable from the CA page.

All material (CA, keys, issued certificates, CRL) is stored in the
`ownca_data` volume (`/var/lib/ownca` inside the container).

## Configuration

Environment variables — in the `.env` file:

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Admin login |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Admin password |
| `OWNCA_PROJECT_NAME` | `OwnCA` | Short project name |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Full title in the topbar |

## Containers

| Container | Image | Description |
|---|---|---|
| `ownca-gh-demo-postgresql` | `postgres:16` | PostgreSQL on port 5433 |
| `ownca-gh-demo-nginx` | `ownca-nginx:latest` | Nginx with GOST + RSA TLS (port 9443) |
| `ownca-gh-demo-dashboard` | `ownca-dashboard:latest` | Django on port 9000 + openssl/gost-engine |

## Ports

| Port | Service |
|---|---|
| `5433` | PostgreSQL |
| `9000` | Django (dashboard) |
| `9443` | nginx → dashboard (GOST + RSA TLS) |

## Architecture

```
Browser ──────> nginx :9443 (GOST + RSA TLS)
                       |
              Dashboard :9000
                  |--> openssl + gost-engine (key generation and signing)
                  |--> /var/lib/ownca  (CA, certificates, CRL on disk)
                  |--> PostgreSQL :5433  (metadata index)
```

All services use `network_mode: host`.

## Stop

```bash
docker compose down
```

Full cleanup (including PostgreSQL data, nginx certificates, and CA
material):

```bash
docker compose down -v
```

---

## `build-images.sh` cheat sheet

| Command | Action |
|---|---|
| `build-images.sh` | Build all images (alias for `build`) |
| `build-images.sh build` | Build all images |
| `build-images.sh build <name>...` | Build selected images |
| `build-images.sh export` | Pack all images + deploy files into `ownca-images.tar.gz` |
| `build-images.sh export <name>...` | Pack selected images + deploy files |
| `build-images.sh import` | Load all images from `docker-images.tar` (extracted archive required) |
| `build-images.sh import <name>...` | Load selected images |
| `build-images.sh all` | `build` + `export` |
| `build-images.sh all <name>...` | `build` + `export` for selected images |
| `build-images.sh help` | Help |

Valid `<name>` values: `dashboard` (`dash`), `nginx`, `postgres` (`pg`).
