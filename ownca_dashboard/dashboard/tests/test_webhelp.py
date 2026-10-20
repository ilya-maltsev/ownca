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

"""Tests for webhelp views and navigation helpers."""
import json

from django.test import TestCase
from django.urls import reverse

from dashboard.tests.conftest import DashboardTestCase
from dashboard.webhelp import nav


class NavHelpersTest(TestCase):

    def test_all_slugs_returns_list(self):
        slugs = nav.all_slugs()
        self.assertIsInstance(slugs, list)
        self.assertTrue(len(slugs) > 0)

    def test_all_slugs_contains_new_slugs(self):
        slugs = nav.all_slugs()
        for expected in ('cert_renew', 'cert_revoke', 'pkcs12_export', 'csr_parse'):
            self.assertIn(expected, slugs, f'{expected!r} missing from nav tree')

    def test_get_page_meta_known_slug(self):
        section, page = nav.get_page_meta('certificates')
        self.assertIsNotNone(section)
        self.assertEqual(page['slug'], 'certificates')

    def test_get_page_meta_unknown_slug(self):
        section, page = nav.get_page_meta('nonexistent_slug_xyz')
        self.assertIsNone(section)
        self.assertIsNone(page)

    def test_help_slug_for_page_mapped(self):
        self.assertEqual(nav.help_slug_for_page('dashboard'), 'dashboard')
        self.assertEqual(nav.help_slug_for_page('cert_renew'), 'cert_renew')
        self.assertEqual(nav.help_slug_for_page('cert_revoke'), 'cert_revoke')
        self.assertEqual(nav.help_slug_for_page('csr_parse'), 'csr_parse')

    def test_help_slug_for_page_fallback(self):
        result = nav.help_slug_for_page('unknown_page_name_xyz')
        self.assertEqual(result, nav.DEFAULT_HELP_SLUG)


class WebhelpRedirectViewTest(TestCase):

    def test_redirect_goes_to_index(self):
        resp = self.client.get(reverse('webhelp_redirect'))
        self.assertIn(resp.status_code, (301, 302))


class WebhelpIndexViewTest(DashboardTestCase):

    def test_en_index_renders(self):
        resp = self.client.get(reverse('webhelp_index', args=['en']))
        self.assertEqual(resp.status_code, 200)

    def test_ru_index_renders(self):
        resp = self.client.get(reverse('webhelp_index', args=['ru']))
        self.assertEqual(resp.status_code, 200)

    def test_unknown_lang_falls_back(self):
        resp = self.client.get(reverse('webhelp_index', args=['xx']))
        self.assertIn(resp.status_code, (200, 302))


class WebhelpPageViewTest(DashboardTestCase):

    def test_known_slug_en_renders(self):
        resp = self.client.get(reverse('webhelp_page', args=['en', 'certificates']))
        self.assertEqual(resp.status_code, 200)

    def test_known_slug_ru_renders(self):
        resp = self.client.get(reverse('webhelp_page', args=['ru', 'certificates']))
        self.assertEqual(resp.status_code, 200)

    def test_new_slug_cert_renew_en(self):
        resp = self.client.get(reverse('webhelp_page', args=['en', 'cert_renew']))
        self.assertEqual(resp.status_code, 200)

    def test_new_slug_cert_revoke_ru(self):
        resp = self.client.get(reverse('webhelp_page', args=['ru', 'cert_revoke']))
        self.assertEqual(resp.status_code, 200)

    def test_new_slug_pkcs12_export_en(self):
        resp = self.client.get(reverse('webhelp_page', args=['en', 'pkcs12_export']))
        self.assertEqual(resp.status_code, 200)

    def test_new_slug_csr_parse_ru(self):
        resp = self.client.get(reverse('webhelp_page', args=['ru', 'csr_parse']))
        self.assertEqual(resp.status_code, 200)

    def test_unknown_slug_returns_404(self):
        resp = self.client.get(reverse('webhelp_page', args=['en', 'nonexistent_xyz']))
        self.assertEqual(resp.status_code, 404)


class WebhelpSearchIndexViewTest(DashboardTestCase):

    def test_en_search_index_is_valid_json(self):
        resp = self.client.get(reverse('webhelp_search_index', args=['en']))
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        # Index is wrapped in {'items': [...]}
        items = data if isinstance(data, list) else data.get('items', data)
        self.assertTrue(len(items) > 0)

    def test_ru_search_index_is_valid_json(self):
        resp = self.client.get(reverse('webhelp_search_index', args=['ru']))
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        items = data if isinstance(data, list) else data.get('items', data)
        self.assertTrue(len(items) > 0)

    def test_search_index_every_slug_present(self):
        resp = self.client.get(reverse('webhelp_search_index', args=['en']))
        data = json.loads(resp.content)
        items = data if isinstance(data, list) else data.get('items', data)
        slugs_in_index = {entry['slug'] for entry in items}
        for slug in nav.all_slugs():
            self.assertIn(slug, slugs_in_index, f'slug {slug!r} missing from search index')
