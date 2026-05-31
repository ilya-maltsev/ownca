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

"""Tests for login_view and logout_view."""
from django.test import TestCase
from django.urls import reverse

from dashboard.tests.conftest import make_superuser


class LoginViewTest(TestCase):

    def setUp(self):
        self.user = make_superuser(username='logintest', password='pw123')

    def test_get_renders_login_form(self):
        resp = self.client.get(reverse('login'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'dashboard/login.html')

    def test_authenticated_user_is_redirected(self):
        self.client.force_login(self.user)
        resp = self.client.get(reverse('login'))
        self.assertRedirects(resp, reverse('dashboard'))

    def test_valid_credentials_log_in_and_redirect(self):
        resp = self.client.post(reverse('login'), {'username': 'logintest', 'password': 'pw123'})
        self.assertRedirects(resp, reverse('dashboard'))

    def test_invalid_credentials_show_error(self):
        resp = self.client.post(reverse('login'), {'username': 'logintest', 'password': 'wrong'})
        self.assertEqual(resp.status_code, 200)
        ctx = resp.context
        self.assertTrue(ctx['error'])

    def test_next_param_honoured(self):
        resp = self.client.post(
            reverse('login') + '?next=' + reverse('cas'),
            {'username': 'logintest', 'password': 'pw123'},
        )
        self.assertRedirects(resp, reverse('cas'))


class LogoutViewTest(TestCase):

    def setUp(self):
        self.user = make_superuser(username='logouttest', password='pw123')
        self.client.force_login(self.user)

    def test_logout_clears_session_and_redirects(self):
        resp = self.client.get(reverse('logout'))
        self.assertRedirects(resp, reverse('login'))
        resp2 = self.client.get(reverse('dashboard'))
        # Unauthenticated → redirect to login
        self.assertNotEqual(resp2.status_code, 200)
