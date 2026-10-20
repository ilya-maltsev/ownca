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

"""Tests for dashboard_view."""
from django.test import TestCase
from django.urls import reverse

from dashboard.tests.conftest import DashboardTestCase


class DashboardViewTest(DashboardTestCase):

    def test_renders_dashboard_template(self):
        resp = self.client.get(reverse('dashboard'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'dashboard/dashboard.html')

    def test_context_has_expected_keys(self):
        resp = self.client.get(reverse('dashboard'))
        for key in ('cas_total', 'certs_total', 'certs_active',
                    'certs_revoked', 'certs_expired', 'pending_count'):
            self.assertIn(key, resp.context)

    def test_anonymous_user_redirected(self):
        self.client.logout()
        resp = self.client.get(reverse('dashboard'))
        self.assertNotEqual(resp.status_code, 200)


class DashboardRequiresLoginTest(TestCase):

    def test_dashboard_without_login_redirects(self):
        resp = self.client.get(reverse('dashboard'))
        self.assertNotEqual(resp.status_code, 200)
