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

"""Tests for CA views: cas_view, ca_create_view, ca_detail_view, ca_delete_view,
ca_download_cert_view, ca_generate_crl_view, ca_download_crl_view."""
from __future__ import annotations

import shutil
import tempfile
import unittest
import uuid

from django.test import override_settings
from django.urls import reverse

from dashboard import own_ca
from dashboard.own_ca import CASpec
from dashboard.models import CertificateAuthority, SystemSettings
from dashboard.tests.conftest import DashboardTestCase, GOST_AVAILABLE


class CasListViewTest(DashboardTestCase):

    def test_renders_ca_list(self):
        resp = self.client.get(reverse('cas'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'dashboard/cas.html')

    def test_key_alg_choices_filtered_by_issuance_modes(self):
        # Disabled key families must not be offered in the CA-create form.
        s = SystemSettings.get_solo()
        s.allow_gost_keys = False
        s.allow_rsa_keys = True
        s.allow_ecdsa_keys = False
        s.save()
        resp = self.client.get(reverse('cas'))
        offered = {v for v, _ in resp.context['key_alg_choices']}
        self.assertIn('rsa:2048', offered)
        self.assertNotIn('gost2012_256', offered)
        self.assertNotIn('ec:P-256', offered)
        self.assertNotIn('ed25519', offered)


class CaCreateKeyFamilyGatingTest(DashboardTestCase):
    """CA creation must honour the issuance-mode key-family toggles, not just
    the custom-cert-issue workflow."""

    def test_create_with_disabled_family_rejected(self):
        s = SystemSettings.get_solo()
        s.allow_ecdsa_keys = False
        s.save()
        resp = self.client.post(reverse('ca_create'), {
            'name': 'Blocked ECDSA CA',
            'common_name': 'Blocked ECDSA CA',
            'ca_type': 'root',
            'key_alg': 'ec:P-256',
            'days': '30',
        })
        self.assertRedirects(resp, reverse('cas'), fetch_redirect_response=False)
        self.assertFalse(
            CertificateAuthority.objects.filter(name='Blocked ECDSA CA').exists()
        )


class CaCreateViewGetTest(DashboardTestCase):

    def test_get_redirects_to_cas(self):
        # ca_create_view redirects non-POST requests back to the CA list
        resp = self.client.get(reverse('ca_create'))
        self.assertRedirects(resp, reverse('cas'), fetch_redirect_response=False)


@unittest.skipUnless(GOST_AVAILABLE, 'GOST engine not available')
class CaCreateRootTest(DashboardTestCase):

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix='ownca_test_ca_create_')
        self._override = override_settings(OWNCA_STORAGE_DIR=self._tmp)
        self._override.enable()

    def tearDown(self):
        self._override.disable()
        shutil.rmtree(self._tmp, ignore_errors=True)
        super().tearDown()

    def test_post_creates_root_ca_and_redirects_to_detail(self):
        resp = self.client.post(reverse('ca_create'), {
            'name': 'Test Create Root',
            'ca_type': 'root',
            'subject': '/CN=Test Create Root',
            'key_alg': 'rsa:2048',
            'days': '30',
        })
        self.assertEqual(CertificateAuthority.objects.filter(name='Test Create Root').count(), 1)
        # After creation, view redirects to the new CA's detail page
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/cas/', resp['Location'])


@unittest.skipUnless(GOST_AVAILABLE, 'GOST engine not available')
class CaDetailViewTest(DashboardTestCase):

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix='ownca_test_detail_')
        self._override = override_settings(OWNCA_STORAGE_DIR=self._tmp)
        self._override.enable()
        self.ca_uuid = str(uuid.uuid4())
        own_ca.create_root_ca(self.ca_uuid, CASpec(
            name='Detail Test CA',
            subject='/CN=Detail Test CA',
            key_alg='rsa:2048',
            days=30,
        ))
        self.ca = CertificateAuthority.objects.create(
            uuid=self.ca_uuid,
            name='Detail Test CA',
            ca_type='root',
            subject='/CN=Detail Test CA',
            key_alg='rsa:2048',
        )

    def tearDown(self):
        self._override.disable()
        shutil.rmtree(self._tmp, ignore_errors=True)
        super().tearDown()

    def test_ca_detail_renders(self):
        resp = self.client.get(reverse('ca_detail', args=[self.ca_uuid]))
        self.assertEqual(resp.status_code, 200)

    def test_ca_download_cert(self):
        resp = self.client.get(reverse('ca_download_cert', args=[self.ca_uuid]))
        self.assertEqual(resp.status_code, 200)
        self.assertIn('application/', resp['Content-Type'])

    def test_ca_generate_crl(self):
        resp = self.client.post(reverse('ca_generate_crl', args=[self.ca_uuid]))
        self.assertRedirects(resp, reverse('ca_detail', args=[self.ca_uuid]),
                             fetch_redirect_response=False)

    def test_ca_download_crl_after_generate(self):
        self.client.post(reverse('ca_generate_crl', args=[self.ca_uuid]))
        resp = self.client.get(reverse('ca_download_crl', args=[self.ca_uuid]))
        self.assertEqual(resp.status_code, 200)

    def test_ca_detail_unknown_uuid_404(self):
        resp = self.client.get(reverse('ca_detail', args=[uuid.uuid4()]))
        self.assertEqual(resp.status_code, 404)
