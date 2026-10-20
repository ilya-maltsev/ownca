# Administrator account

OwnCA operates with a single superuser account. There is no user
management UI — the account is provisioned automatically from
environment variables.

## Credentials

| Variable | Default | Purpose |
|---|---|---|
| `DASHBOARD_ADMIN_USER` | `admin` | Login name. |
| `DASHBOARD_ADMIN_PASSWORD` | `admin` | Password. |

The defaults are only fit for a test rig. Set your own before the
first start — in `dev_env/.env` or the container environment.

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

The session cookie is set with `HttpOnly` and `SameSite=Strict` and is
dropped when the browser closes. The `Secure` flag is set unless
`DJANGO_SECURE_COOKIES=False` (it is off in `dev_env/` so that plain HTTP
on port 8001 keeps working).

## Related topics

* [Configuration](configuration.md)
* [Maintenance](maintenance.md)
