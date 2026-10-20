# This file is a part of OwnCA,
# Certificate Authority GUI based on Django and OpenSSL 
#
# Copyright (C) 2026 Ilya Maltsev
# email: i.y.maltsev@yandex.ru
#
# OwnCA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OwnCA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OwnCA.  If not, see <http://www.gnu.org/licenses/>.


import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-dev-key-change-in-production')
DEBUG = os.environ.get('DJANGO_DEBUG', 'True').lower() in ('true', '1', 'yes')
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '*').split(',')
CSRF_TRUSTED_ORIGINS = os.environ.get('CSRF_TRUSTED_ORIGINS', 'http://127.0.0.1:8000,http://localhost:8000').split(',')

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'dashboard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'dashboard.context_processors.branding',
                'dashboard.context_processors.webhelp_context',
                'dashboard.context_processors.system_settings',
                'dashboard.context_processors.cryptopro_context',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'ownca'),
        'USER': os.environ.get('DB_USER', 'ownca'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'ownca'),
        'HOST': os.environ.get('DB_HOST', '127.0.0.1'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

from django.utils.translation import gettext_lazy as _

LANGUAGE_CODE = 'ru'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

LANGUAGES = [
    ('ru', _('Russian')),
    ('en', _('English')),
]

LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

DASHBOARD_ADMIN_USER = os.environ.get('DASHBOARD_ADMIN_USER', 'admin')
DASHBOARD_ADMIN_PASSWORD = os.environ.get('DASHBOARD_ADMIN_PASSWORD', 'admin')

# Branding ------------------------------------------------------------------
OWNCA_PROJECT_TITLE = os.environ.get('OWNCA_PROJECT_TITLE', 'Own Certificate Authority')

# OwnCA backend -------------------------------------------------------------
OWNCA_STORAGE_DIR = os.environ.get('OWNCA_STORAGE_DIR', '/var/lib/ownca')
OWNCA_OPENSSL_BIN = os.environ.get('OWNCA_OPENSSL_BIN', 'openssl')
OWNCA_DEFAULT_KEY_ALG = os.environ.get('OWNCA_DEFAULT_KEY_ALG', 'gost2012_256')
OWNCA_DEFAULT_CA_DAYS = int(os.environ.get('OWNCA_DEFAULT_CA_DAYS', '3650'))
OWNCA_DEFAULT_CERT_DAYS = int(os.environ.get('OWNCA_DEFAULT_CERT_DAYS', '365'))
OWNCA_CRL_DISTRIBUTION = os.environ.get('OWNCA_CRL_DISTRIBUTION', '')

# CryptoPro CSP backend -----------------------------------------------------
# Optional certified-GOST backend. Layered gating:
#   1. BUILD-time  : the image only carries CryptoPro if the .deb distribution
#      was staged into the build context; the Dockerfile then writes the marker
#      file named by OWNCA_CRYPTOPRO_MARKER. cryptopro.available() checks it.
#   2. RUNTIME     : OWNCA_CRYPTOPRO_ENABLED must be truthy to actually route
#      GOST ops to CryptoPro. If the marker is absent the flag is inert.
# When both hold, GOST key-gen / issuance / CRL / PKCS#12 run on CryptoPro CSP
# (CAPILite) instead of openssl+gost-engine; non-GOST always stays on openssl.
OWNCA_CRYPTOPRO_ENABLED = os.environ.get('OWNCA_CRYPTOPRO_ENABLED', 'False').lower() in ('true', '1', 'yes', 'on')
# The test suite validates the openssl backend; keep it deterministic even when
# the image happens to ship CryptoPro with the runtime flag on. The dedicated
# CryptoPro tests override this per-case where they need the enabled state.
if 'test' in sys.argv:
    OWNCA_CRYPTOPRO_ENABLED = False
# Marker file written by the Dockerfile when CryptoPro packages were installed.
# Deliberately NOT under /opt/app: the dev stack bind-mounts the source over
# /opt/app, which would shadow anything the image baked there.
OWNCA_CRYPTOPRO_MARKER = os.environ.get('OWNCA_CRYPTOPRO_MARKER', '/opt/ownca/.cryptopro_available')
# CryptoPro install roots (defaults match the lsb-cprocsp-* Debian layout).
OWNCA_CRYPTOPRO_ROOT = os.environ.get('OWNCA_CRYPTOPRO_ROOT', '/opt/cprocsp')
# DRBG "gamma" (external entropy, CPSD reader). CryptGenKey consumes 36 bytes
# per key; the UI counter = filesize / 36. Path holds the kis_1 pools.
OWNCA_CRYPTOPRO_GAMMA_DIR = os.environ.get('OWNCA_CRYPTOPRO_GAMMA_DIR', '/var/opt/cprocsp/dsrf')
# License serial. If empty, CryptoPro runs on its built-in 90-day demo license.
# A serial persisted via the web UI (CryptoProSettings) overrides this env value.
OWNCA_CRYPTOPRO_LICENSE = os.environ.get('OWNCA_CRYPTOPRO_LICENSE', '')
# The C-shim binary that bridges own_ca.py to CAPILite (built in the Dockerfile).
# Also outside /opt/app for the bind-mount reason above.
OWNCA_CRYPTOPRO_SHIM_BIN = os.environ.get('OWNCA_CRYPTOPRO_SHIM_BIN', '/opt/ownca/bin/ownca_capi')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Session & cookie hardening ------------------------------------------------
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SECURE = os.environ.get('DJANGO_SECURE_COOKIES', 'True').lower() in ('true', '1', 'yes')
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

_upload_max_mb = int(os.environ.get('UPLOAD_MAX_MB', '10'))
DATA_UPLOAD_MAX_MEMORY_SIZE = _upload_max_mb * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = _upload_max_mb * 1024 * 1024

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'dashboard': {
            'handlers': ['console'],
            'level': os.environ.get('DJANGO_LOG_LEVEL', 'INFO'),
        },
    },
}
