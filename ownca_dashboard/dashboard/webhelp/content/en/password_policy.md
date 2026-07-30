# Password management

There is no password policy UI. The superuser password is managed
through environment variables.

## Setting the password

Set `DASHBOARD_ADMIN_PASSWORD=<new_password>` in `docker-compose.yml`
(or the environment) and restart the container — the value is
applied at the next start.

## Password strength

The built-in validators are always active:

* Minimum length.
* Common-password check.
* Numeric-only check.
* User-attribute similarity check.

## Related topics

* [Administrator account](users.md)
* [Configuration](configuration.md)
