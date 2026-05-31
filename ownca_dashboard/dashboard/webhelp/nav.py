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

"""Webhelp navigation tree and dashboard→help slug mapping.

Single source of truth for:
* the section tree rendered in the webhelp sidebar,
* per-language page titles,
* the mapping from dashboard URL ``name`` to the help slug used by the
  context-aware ``Help`` button in the dashboard sidebar.
"""
from __future__ import annotations


# Section tree. Each section has a translatable title (per language) and a
# list of pages (slug + per-language titles). Order is preserved.
HELP_NAV_TREE = [
    {
        'id': 'getting_started',
        'title': {'ru': 'Начало работы', 'en': 'Getting started'},
        'pages': [
            {'slug': 'getting_started',
             'title': {'ru': 'Вход и первое подключение',
                       'en': 'Login and first connection'}},
            {'slug': 'concepts',
             'title': {'ru': 'Основные понятия PKI',
                       'en': 'PKI concepts'}},
        ],
    },
    {
        'id': 'monitoring',
        'title': {'ru': 'Мониторинг', 'en': 'Monitoring'},
        'pages': [
            {'slug': 'dashboard',
             'title': {'ru': 'Обзорная панель',
                       'en': 'Dashboard overview'}},
        ],
    },
    {
        'id': 'cert_ops',
        'title': {'ru': 'Операции с сертификатами',
                  'en': 'Certificate operations'},
        'pages': [
            {'slug': 'certificates',
             'title': {'ru': 'Реестр сертификатов',
                       'en': 'Certificate registry'}},
            {'slug': 'custom_cert_issue',
             'title': {'ru': 'Выпуск произвольного сертификата',
                       'en': 'Custom Cert Issue'}},
            {'slug': 'cert_renew',
             'title': {'ru': 'Продление сертификата',
                       'en': 'Certificate renewal'}},
            {'slug': 'cert_revoke',
             'title': {'ru': 'Отзыв и CRL',
                       'en': 'Revocation and CRL'}},
            {'slug': 'pkcs12_export',
             'title': {'ru': 'Экспорт PKCS#12',
                       'en': 'PKCS#12 export'}},
            {'slug': 'csr_parse',
             'title': {'ru': 'Инструмент разбора CSR',
                       'en': 'CSR parse tool'}},
        ],
    },
    {
        'id': 'ca',
        'title': {'ru': 'Удостоверяющий центр',
                  'en': 'Certification authority'},
        'pages': [
            {'slug': 'cas',
             'title': {'ru': 'Управление УЦ',
                       'en': 'CA management'}},
        ],
    },
    {
        'id': 'profiles',
        'title': {'ru': 'Профили и расширения',
                  'en': 'Profiles and extensions'},
        'pages': [
            {'slug': 'cert_profiles',
             'title': {'ru': 'Профили сертификатов',
                       'en': 'Certificate profiles'}},
        ],
    },
    {
        'id': 'system',
        'title': {'ru': 'Система', 'en': 'System'},
        'pages': [
            {'slug': 'users',
             'title': {'ru': 'Учётная запись администратора',
                       'en': 'Administrator account'}},
            {'slug': 'password_policy',
             'title': {'ru': 'Управление паролем',
                       'en': 'Password management'}},
            {'slug': 'configuration',
             'title': {'ru': 'Конфигурация',
                       'en': 'Configuration'}},
            {'slug': 'maintenance',
             'title': {'ru': 'Обслуживание',
                       'en': 'Maintenance'}},
        ],
    },
    {
        'id': 'reference',
        'title': {'ru': 'Справочник', 'en': 'Reference'},
        'pages': [
            {'slug': 'x509_overview',
             'title': {'ru': 'Структура X.509-сертификата',
                       'en': 'X.509 certificate structure'}},
            {'slug': 'key_usage',
             'title': {'ru': 'Key Usage и Extended Key Usage',
                       'en': 'Key Usage and Extended Key Usage'}},
            {'slug': 'distribution_points',
             'title': {'ru': 'Точки распространения (CDP/AIA/SIA)',
                       'en': 'Distribution points (CDP/AIA/SIA)'}},
            {'slug': 'gost_algorithms',
             'title': {'ru': 'ГОСТ-алгоритмы',
                       'en': 'GOST algorithms'}},
            {'slug': 'glossary',
             'title': {'ru': 'Глоссарий', 'en': 'Glossary'}},
        ],
    },
]


# Maps dashboard URL ``name`` (i.e. ``page`` template variable) to a help
# slug. Used by the contextual ``Help`` button in the dashboard sidebar.
HELP_PAGE_MAP = {
    'dashboard': 'dashboard',
    'login': 'getting_started',

    'certificates': 'certificates',
    'cert_detail': 'certificates',
    'cert_renew': 'cert_renew',
    'cert_revoke': 'cert_revoke',
    'cert_download': 'pkcs12_export',
    'csr_parse': 'csr_parse',
    'custom_cert_issue': 'custom_cert_issue',

    'cas': 'cas',
    'ca_create': 'cas',
    'ca_detail': 'cas',

    'cert_profiles': 'cert_profiles',
    'cert_profile_detail': 'cert_profiles',

    'configuration': 'configuration',
    'maintenance': 'maintenance',
}

DEFAULT_HELP_SLUG = 'getting_started'
SUPPORTED_LANGS = ('ru', 'en')


def get_page_meta(slug: str):
    """Return ``(section, page)`` dicts for ``slug``, or ``(None, None)``."""
    for section in HELP_NAV_TREE:
        for page in section['pages']:
            if page['slug'] == slug:
                return section, page
    return None, None


def all_slugs():
    return [p['slug'] for s in HELP_NAV_TREE for p in s['pages']]


def help_slug_for_page(page_name: str) -> str:
    """Resolve dashboard ``page`` name to a help slug, falling back to the
    default landing slug if the page is not mapped."""
    return HELP_PAGE_MAP.get(page_name, DEFAULT_HELP_SLUG)
