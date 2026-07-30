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

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import mistune
from django.http import Http404, JsonResponse
from django.shortcuts import redirect, render
from django.utils.translation import get_language

from .nav import (
    DEFAULT_HELP_SLUG,
    HELP_NAV_TREE,
    SUPPORTED_LANGS,
    all_slugs,
    get_page_meta,
)


CONTENT_DIR = Path(__file__).resolve().parent / 'content'


def _normalise_lang(lang: str) -> str:
    lang = (lang or '').lower()
    return lang if lang in SUPPORTED_LANGS else 'ru'


# Rewrites <a href="foo.md"> and <a href="foo.md#anchor"> to <a href="foo/">
# so cross-page links inside markdown resolve to the canonical help URL
# ``/webhelp/<lang>/<slug>/``. External URLs (http/https/mailto) are left
# untouched.
_MD_LINK_RE = re.compile(
    r'(<a\b[^>]*\bhref=")(?!https?://|mailto:|#|/)([^"#]+?)\.md(#[^"]*)?(")'
)


def _rewrite_md_links(html: str) -> str:
    # Emit ``../<slug>/`` so links inside the rendered markdown resolve to a
    # sibling help page under ``/webhelp/<lang>/<slug>/`` regardless of which
    # page is currently being viewed.
    return _MD_LINK_RE.sub(lambda m: f'{m.group(1)}../{m.group(2)}/{m.group(3) or ""}{m.group(4)}', html)


@lru_cache(maxsize=128)
def _render_markdown(lang: str, slug: str) -> tuple[str, str]:
    """Return ``(html, plain_excerpt)`` for the given page. Raises
    ``FileNotFoundError`` when the markdown file is missing.

    The cache is per-process and cleared by restarting the worker; in dev
    Django's autoreloader picks up file changes on .py edits but the markdown
    cache stays warm — call ``_render_markdown.cache_clear()`` from a shell
    or restart the container to refresh content while iterating.
    """
    path = CONTENT_DIR / lang / f'{slug}.md'
    text = path.read_text(encoding='utf-8')
    html = mistune.html(text)
    html = _rewrite_md_links(html)
    plain = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html)).strip()
    excerpt = plain[:240] + ('…' if len(plain) > 240 else '')
    return html, excerpt


def _build_breadcrumbs(lang: str, slug: str):
    section, page = get_page_meta(slug)
    if not page:
        return []
    return [
        {'title': section['title'][lang], 'slug': None},
        {'title': page['title'][lang], 'slug': slug},
    ]


def _localized_tree(lang: str):
    return [
        {
            'id': s['id'],
            'title': s['title'][lang],
            'pages': [
                {'slug': p['slug'], 'title': p['title'][lang]}
                for p in s['pages']
            ],
        }
        for s in HELP_NAV_TREE
    ]


def webhelp_redirect_view(request):
    """``/webhelp/`` → redirects to the index for the current language."""
    lang = _normalise_lang(get_language())
    return redirect('webhelp_index', lang=lang)


def webhelp_index_view(request, lang: str):
    """``/webhelp/<lang>/`` → table of contents."""
    lang = _normalise_lang(lang)
    context = {
        'lang': lang,
        'tree': _localized_tree(lang),
        'active_slug': None,
        'breadcrumbs': [],
        'page_title': {'ru': 'Справка',
                       'en': 'Help'}[lang],
        'is_index': True,
    }
    return render(request, 'webhelp/index.html', context)


def webhelp_page_view(request, lang: str, slug: str):
    """``/webhelp/<lang>/<slug>/`` → render a single help page."""
    lang = _normalise_lang(lang)
    section, page = get_page_meta(slug)
    if not page:
        raise Http404(f'Unknown help page: {slug}')

    try:
        html, _ = _render_markdown(lang, slug)
    except FileNotFoundError:
        # Fall back to the other language so half-translated content is still
        # usable instead of a 404.
        other = 'en' if lang == 'ru' else 'ru'
        try:
            html, _ = _render_markdown(other, slug)
            html = (f'<div class="webhelp-note webhelp-note-warning">'
                    f'<strong>{"Note" if lang == "en" else "Внимание"}:</strong> '
                    f'{"This page is not yet translated." if lang == "en" else "Эта страница ещё не переведена."}'
                    f'</div>') + html
        except FileNotFoundError:
            raise Http404(f'Help content missing: {slug}')

    context = {
        'lang': lang,
        'tree': _localized_tree(lang),
        'active_slug': slug,
        'active_section_id': section['id'],
        'breadcrumbs': _build_breadcrumbs(lang, slug),
        'page_title': page['title'][lang],
        'content_html': html,
        'is_index': False,
    }
    return render(request, 'webhelp/page.html', context)


def webhelp_search_index_view(request, lang: str):
    """JSON index consumed by client-side search."""
    lang = _normalise_lang(lang)
    items = []
    for section in HELP_NAV_TREE:
        for page in section['pages']:
            try:
                _, excerpt = _render_markdown(lang, page['slug'])
            except FileNotFoundError:
                excerpt = ''
            items.append({
                'slug': page['slug'],
                'title': page['title'][lang],
                'section': section['title'][lang],
                'excerpt': excerpt,
            })
    return JsonResponse({'items': items})
