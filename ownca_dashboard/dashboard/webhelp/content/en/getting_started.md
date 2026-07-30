# Login and first connection

This section walks through the first run of the OwnCA web UI, sign-in,
and a quick orientation tour.

## Prerequisites

* A deployed OwnCA instance (see the project README and `dev_env/`).
* A modern browser with TLS support — for GOST cipher suites use the
  bundled nginx front-end from `dev_env/nginx/`, built with
  [`gost-engine`](https://github.com/gost-engine/engine).

## First sign-in

1. Open the deployment URL (`https://localhost:8443` by default).
2. Enter the username and password on `/login/`.
3. After authentication you land on the dashboard at `/`.

> The default administrator account — `admin` / `admin` — is
> provisioned automatically. **Change the credentials before the
> first start** by editing `DASHBOARD_ADMIN_USER` /
> `DASHBOARD_ADMIN_PASSWORD` in `dev_env/.env` (or the environment)
> and restarting the container. There is no in-app password-change
> form — the values are re-applied from the env on every start. See
> [Administrator account](users.md).

## Layout

| Area | Purpose |
|---|---|
| Left sidebar | Navigation, language switcher, Help button, logout. |
| Top bar | Title of the current page and project name. |
| Main area | Tables, forms, and detail views for the current section. |
| `Help` link in the sidebar | Opens contextual help in a new tab. |

## Language switch

A `RU / EN` toggle lives in the sidebar between the navigation
sections and the Help link. The choice applies to the whole UI and
to the help portal.

## What's next

* [CA management](cas.md) — create your first root CA.
* [Custom Cert Issue](custom_cert_issue.md) — direct issuance.
* [Certificate profiles](cert_profiles.md) — define extension templates.
