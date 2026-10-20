# Password management

There is no password policy UI. The superuser password is managed
through environment variables.

## Setting the password

Set `DASHBOARD_ADMIN_PASSWORD=<new_password>` in `dev_env/.env` (or the
container environment) and restart the container — the new value is
applied at start-up.

## Password strength

The password from the environment variable is set as is: length,
complexity and the common-password list are **not checked** (otherwise
the default `admin` password would not work). Choosing a strong password
is up to you.

## Related topics

* [Administrator account](users.md)
* [Configuration](configuration.md)
