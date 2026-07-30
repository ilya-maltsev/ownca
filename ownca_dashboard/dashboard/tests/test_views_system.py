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

"""Tests for configuration_view, maintenance_view, maintenance_refresh_api,
ca_cert_profiles_api."""
import json

from django.urls import reverse

from dashboard.models import Certificate, CertificateAuthority, SystemSettings
from dashboard.tests.conftest import DashboardTestCase, make_cert_profile
from dashboard.tests.conftest import DashboardTestCase


class ConfigurationViewTest(DashboardTestCase):

    def test_get_renders(self):
        resp = self.client.get(reverse('configuration'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'dashboard/configuration.html')

    def test_context_has_storage_dir(self):
        resp = self.client.get(reverse('configuration'))
        self.assertIn('storage_dir', resp.context)

    def test_context_has_sys_settings(self):
        resp = self.client.get(reverse('configuration'))
        self.assertIn('sys_settings', resp.context)

    def test_post_saves_toggles_and_redirects(self):
        # All checkboxes absent => all False
        resp = self.client.post(reverse('configuration'), data={})
        self.assertRedirects(resp, reverse('configuration'))
        s = SystemSettings.get_solo()
        self.assertFalse(s.allow_server_key_generation)
        self.assertFalse(s.allow_gost_keys)
        self.assertFalse(s.allow_rsa_keys)
        self.assertFalse(s.allow_ecdsa_keys)
        self.assertFalse(s.offer_gost_p12_export)
        self.assertFalse(s.disable_cert_profile_protection)

    def test_post_saves_selected_toggles(self):
        resp = self.client.post(reverse('configuration'), data={
            'allow_server_key_generation': 'on',
            'allow_rsa_keys': 'on',
        })
        self.assertRedirects(resp, reverse('configuration'))
        s = SystemSettings.get_solo()
        self.assertTrue(s.allow_server_key_generation)
        self.assertFalse(s.allow_gost_keys)
        self.assertTrue(s.allow_rsa_keys)
        self.assertFalse(s.allow_ecdsa_keys)


class MaintenanceViewTest(DashboardTestCase):

    def test_get_renders(self):
        resp = self.client.get(reverse('maintenance'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'dashboard/maintenance.html')


class MaintenanceRefreshApiTest(DashboardTestCase):

    def test_post_returns_json(self):
        resp = self.client.post(reverse('maintenance_refresh'))
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        # The API returns refreshed/errors counts
        self.assertIn('refreshed', data)

    def test_get_returns_405(self):
        resp = self.client.get(reverse('maintenance_refresh'))
        self.assertEqual(resp.status_code, 405)


class CaCertProfilesApiTest(DashboardTestCase):
    """ca_cert_profiles_api — returns JSON list of non-CA profiles."""

    def setUp(self):
        super().setUp()
        from dashboard.models import CertificateAuthority
        import uuid
        self.ca = CertificateAuthority.objects.create(
            uuid=uuid.uuid4(),
            name='API Test CA',
            ca_type='root',
            subject='/CN=API Test CA',
            key_alg='rsa:2048',
        )
        self.profile = make_cert_profile()

    def test_returns_json_with_profiles(self):
        resp = self.client.get(reverse('ca_cert_profiles', args=[self.ca.uuid]))
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertIn('profiles', data)
        self.assertGreaterEqual(len(data['profiles']), 1)

    def test_unknown_ca_returns_404(self):
        import uuid
        resp = self.client.get(reverse('ca_cert_profiles', args=[uuid.uuid4()]))
        self.assertEqual(resp.status_code, 404)


class CustomCertIssueFreeFormGatingTest(DashboardTestCase):
    """Free-form (no profile) issuance must be gated by
    ``SystemSettings.disable_cert_profile_protection``."""

    def setUp(self):
        super().setUp()
        import uuid
        self.ca = CertificateAuthority.objects.create(
            uuid=uuid.uuid4(),
            name='Gating CA',
            ca_type='root',
            subject='/CN=Gating CA',
            key_alg='rsa:2048',
        )

    def test_get_context_disallows_free_form_by_default(self):
        resp = self.client.get(reverse('custom_cert_issue'))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context['allow_free_form'])

    def test_get_context_allows_free_form_when_enabled(self):
        s = SystemSettings.get_solo()
        s.disable_cert_profile_protection = True
        s.save()
        resp = self.client.get(reverse('custom_cert_issue'))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context['allow_free_form'])

    def test_post_without_profile_rejected_when_protection_on(self):
        resp = self.client.post(reverse('custom_cert_issue'), {
            'ca': str(self.ca.uuid),
            'common_name': 'example.org',
            'cert_profile': '',
        })
        self.assertRedirects(resp, reverse('custom_cert_issue'))
        self.assertFalse(Certificate.objects.exists())

    def test_issue_form_renders_wizard(self):
        """The free-form issue page is wrapped in the client-side wizard:
        a steps-strip plus per-step panels (the single POST is unchanged)."""
        resp = self.client.get(reverse('custom_cert_issue'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'steps-strip')
        self.assertContains(resp, 'wizard-step')
        self.assertContains(resp, 'id="btn-next"')
