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

from django.conf import settings as django_settings
from django.urls import NoReverseMatch, resolve, reverse
from django.utils.translation import get_language


def branding(request):
    return {
        'project_title': django_settings.OWNCA_PROJECT_TITLE,
    }


def system_settings(request):
    """Inject the singleton SystemSettings row so templates can gate UI on
    flags like ``disable_cert_profile_protection``."""
    if not request.user.is_authenticated:
        return {}
    from dashboard.models import SystemSettings
    return {'system_settings': SystemSettings.get_solo()}


def webhelp_context(request):
    """Resolve the contextual help URL for the current dashboard page so the
    sidebar's ``Help`` button can deep-link straight to the relevant topic."""
    from dashboard.webhelp.nav import (
        DEFAULT_HELP_SLUG,
        SUPPORTED_LANGS,
        help_slug_for_page,
    )

    lang = (get_language() or 'ru').split('-')[0]
    if lang not in SUPPORTED_LANGS:
        lang = 'ru'

    page_name = ''
    try:
        match = resolve(request.path_info)
        page_name = match.url_name or ''
    except Exception:
        pass

    slug = help_slug_for_page(page_name) if page_name else DEFAULT_HELP_SLUG
    try:
        url = reverse('webhelp_page', kwargs={'lang': lang, 'slug': slug})
    except NoReverseMatch:
        url = reverse('webhelp_index', kwargs={'lang': lang})
    return {'webhelp_url': url, 'webhelp_lang': lang, 'webhelp_slug': slug}
