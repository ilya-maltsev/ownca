#!/bin/sh
set -e

echo "[i18n] Compiling translation files..."
python manage.py compilemessages

echo "[static] Collecting static files..."
python manage.py collectstatic --noinput

echo "[db] Applying migrations..."
python manage.py migrate --noinput

echo "[admin] Ensuring admin user..."
python manage.py ensure_admin

echo "[runserver] Starting Django dev server on ${BIND_ADDRESS}..."
exec python manage.py runserver "${BIND_ADDRESS}"
