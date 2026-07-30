# OwnCA — Demo Environment

[Русский](README.md) | **English**

---

Environment for demonstrations: the stack comes up with a single command from
pre-built images. The product itself is described in the root
[README](../README.en.md).

Two scenarios, both served by `build-images.sh`:

1. **Locally** — build the images on this machine and bring the stack up.
2. **Transfer to an air-gapped host** — build once, pack everything with the
   deploy files into a single `tar.gz`, copy it to a server without internet
   access, and deploy there.

## 1. Local build and run

```bash
cd demo
bash build-images.sh          # = build-images.sh build
docker compose up -d
```

The build pulls `postgres:16` and builds two images: `ownca-nginx:latest`
(nginx with GOST TLS) and `ownca-dashboard:latest` (Django +
openssl/gost-engine); the Dockerfiles come from `dev_env/`. The build context is
assembled from a whitelist (`DASHBOARD_FILES`, `NGINX_FILES` in the script) —
docs, `.git`, dev tooling and runtime data stay out of the images.

First start takes ~30 seconds: database and `ownca` user initialization, GOST +
RSA PKI generation for nginx, then `compilemessages` + `collectstatic` +
`migrate` + `ensure_admin` + `cryptopro_setup` (a no-op without CryptoPro).

The panel is at `https://localhost:9443`, login `admin` / `admin`.

### Building individual images

```bash
bash build-images.sh build dashboard      # only ownca-dashboard
bash build-images.sh build dash nginx     # several at once
```

Short names: `dashboard` (`dash`), `nginx`, `postgres` (`pg`).

## 2. Transfer to an air-gapped host

```bash
# on the build machine
cd demo
bash build-images.sh all                  # build + export

# on the target host
tar xzf ownca-images.tar.gz -C /opt/
cd /opt/demo
bash build-images.sh import
docker compose up -d
```

`export` puts everything into a single file, `demo/ownca-images.tar.gz`:
`docker-images.tar` (`docker save` of all images) plus the deploy files
(`DEPLOY_PATHS` in the script) — the script itself, `docker-compose.yml`,
`.env.example`, `init-db.sh`, `nginx.conf` and the READMEs. Sources, `.git` and
the dev environment stay on the build machine. `import` loads the images via
`docker load` and removes the temporary tar.

All three commands take an optional selection: `build-images.sh export
dashboard`, `build-images.sh import nginx pg`, `build-images.sh all dashboard`.

### `build-images.sh` cheat sheet

| Command | Action |
|---|---|
| `build-images.sh [build] [<name>...]` | Build all or selected images |
| `build-images.sh export [<name>...]` | Pack images + deploy files into `ownca-images.tar.gz` |
| `build-images.sh import [<name>...]` | Load images from an extracted `docker-images.tar` |
| `build-images.sh all [<name>...]` | `build` + `export` |
| `build-images.sh help` | Help |

## The stack

| Container | Image | Port |
|---|---|---|
| `ownca-gh-demo-postgresql` | `postgres:16` | 5433 |
| `ownca-gh-demo-nginx` | `ownca-nginx:latest` | 9443 (GOST + RSA TLS) |
| `ownca-gh-demo-dashboard` | `ownca-dashboard:latest` | 9000 (Django) |

```
Browser ──> nginx :9443 (GOST + RSA TLS)
                |
          Dashboard :9000
                |--> openssl + gost-engine    (key generation and signing)
                |--> CryptoPro CSP / CAPILite (optional — the GOST CA path)
                |--> /var/lib/ownca           (CAs, certificates, CRLs on disk)
                |--> PostgreSQL :5433         (metadata index)
```

All services run with `network_mode: host`, so ports 5433/9000/9443 are taken on
the host itself. The Compose project is pinned to `ownca_gh_demo`, so container,
volume and network names do not depend on the name of the directory the archive
was unpacked into.

## Configuration

Variables go into a `.env` file next to `docker-compose.yml`; `.env.example` is
the template.

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Admin login |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Admin password |
| `OWNCA_PROJECT_TITLE` | `Own Certificate Authority` | Title in the topbar |
| `OWNCA_CRYPTOPRO_ENABLED` | `False` | Enable the CryptoPro CSP backend (effective only when it is baked into the image) |
| `OWNCA_CRYPTOPRO_LICENSE` | — | Licence serial (empty → 90-day demo; a serial set in the panel wins) |

The full list of application variables is in
[ownca_dashboard/README.en.md](../ownca_dashboard/README.en.md).

## Data and volumes

| Volume | Contents |
|---|---|
| `ownca_gh_demo_data` | `/var/lib/ownca` — CAs, openssl CA keys, issued certificates, CRLs |
| `ownca_gh_demo_pg_data` | PostgreSQL metadata index |
| `ownca_gh_demo_certs` | nginx's own PKI |
| `ownca_gh_demo_cryptopro_keys` | CryptoPro key containers (`/var/opt/cprocsp/keys`) |
| `ownca_gh_demo_cryptopro_gamma` | CryptoPro DRBG gamma (`/var/opt/cprocsp/dsrf`) |

Published CRLs are additionally bind-mounted from the `demo/crls/` directory.

```bash
docker compose down      # stop, data kept
docker compose down -v   # full cleanup, including CryptoPro keys and gamma
```

> The keys of a CryptoPro-backed CA are **not** in `ownca_gh_demo_data` but in
> `ownca_gh_demo_cryptopro_keys`. Both volumes have to be backed up, otherwise a
> restored CA cannot sign anything — and `down -v` destroys them irrecoverably.

## CryptoPro CSP backend (optional)

If the CryptoPro distribution (a `.tgz` with `.deb` packages) is available when
the dashboard image is built, it gets baked in: the packages are installed and
the `ownca_capi` CAPILite C bridge is compiled. The default path is
`dev_env/cryptopro_linux-amd64_deb.tgz`:

```bash
OWNCA_CRYPTOPRO_DIST=/path/to/cryptopro_linux-amd64_deb.tgz bash build-images.sh build dashboard
OWNCA_CRYPTOPRO_DIST=none bash build-images.sh   # force a build WITHOUT CryptoPro
```

Without the distribution the image is built without CryptoPro (with an explicit
message) and all GOST operations stay on openssl + gost-engine.

With CryptoPro baked in and `OWNCA_CRYPTOPRO_ENABLED=True`, provider management
appears in the panel: status, licence, remaining DRBG gamma and gamma upload.
Gamma is mandatory for key generation — upload it or generate test gamma (test
rigs only). Backend limitations are in the root
[README](../README.en.md#cryptopro-backend-limitations).

Working through the panel is covered by the built-in contextual help, opened
straight from the interface.
