# Administrator account

OwnCA operates with a single superuser account. There is no user
management UI — the account is provisioned automatically from
environment variables.

## Credentials

| Variable | Default | Purpose |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Login name. |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Password. |

Set these in `docker-compose.yml` (or the environment) before the
first start, then change them to strong values.

## Provisioning

On every container start the admin account is provisioned
automatically:

1. The superuser is created if it does not exist.
2. The password is updated to the current value of
   `DASHBOARD_ADMIN_PASSWORD`.
3. Any stale non-superuser accounts are removed.

## Password rotation

Update `DASHBOARD_ADMIN_PASSWORD` and restart the container — the
provisioning step will apply the new value.

## Session security

Sessions are protected by cookie hardening: `HttpOnly`, `SameSite=Strict`,
`Secure`, and the cookie expires when the browser closes.

## Related topics

* [Configuration](configuration.md)
* [Maintenance](maintenance.md)
