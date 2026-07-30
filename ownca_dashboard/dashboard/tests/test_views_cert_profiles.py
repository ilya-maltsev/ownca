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

"""Tests for cert profile views."""
from __future__ import annotations

from django.urls import reverse

from dashboard.models import CertProfile
from dashboard.tests.conftest import DashboardTestCase, make_cert_profile


class CertProfilesListTest(DashboardTestCase):

    def test_list_renders(self):
        resp = self.client.get(reverse('cert_profiles'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'dashboard/cert_profiles.html')


class CertProfileDetailTest(DashboardTestCase):

    def setUp(self):
        super().setUp()
        self.profile = make_cert_profile()

    def test_detail_get_renders_form(self):
        resp = self.client.get(reverse('cert_profile_detail', args=[self.profile.pk]))
        self.assertEqual(resp.status_code, 200)

    def test_detail_404_on_unknown(self):
        resp = self.client.get(reverse('cert_profile_detail', args=[999999]))
        self.assertEqual(resp.status_code, 404)

    def test_detail_post_updates_profile(self):
        resp = self.client.post(
            reverse('cert_profile_detail', args=[self.profile.pk]),
            {
                'display_name': 'Updated Name',
                'name': self.profile.name,
                'eku': 'serverAuth',
                'ku_digital_signature': 'on',
            },
        )
        self.assertRedirects(
            resp, reverse('cert_profile_detail', args=[self.profile.pk]),
            fetch_redirect_response=False,
        )
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.display_name, 'Updated Name')


class CertProfileCopyTest(DashboardTestCase):

    def setUp(self):
        super().setUp()
        self.profile = make_cert_profile()

    def test_copy_creates_new_profile(self):
        before = CertProfile.objects.count()
        resp = self.client.post(reverse('cert_profile_copy', args=[self.profile.pk]))
        self.assertEqual(CertProfile.objects.count(), before + 1)

    def test_copy_404_on_unknown(self):
        resp = self.client.post(reverse('cert_profile_copy', args=[999999]))
        self.assertEqual(resp.status_code, 404)


class CertProfileDeleteTest(DashboardTestCase):

    def setUp(self):
        super().setUp()
        self.profile = make_cert_profile()

    def test_delete_removes_profile(self):
        pk = self.profile.pk
        resp = self.client.post(reverse('cert_profile_delete', args=[pk]))
        self.assertFalse(CertProfile.objects.filter(pk=pk).exists())

    def test_delete_get_redirects_to_profiles(self):
        # cert_profile_delete_view redirects non-POST back to cert_profiles list
        resp = self.client.get(reverse('cert_profile_delete', args=[self.profile.pk]))
        self.assertRedirects(resp, reverse('cert_profiles'), fetch_redirect_response=False)
