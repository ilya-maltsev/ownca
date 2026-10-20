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

"""Tests that the seed migration (0002_seed_demo) produced the expected state."""
from django.test import TestCase

from dashboard.models import CertProfile, CustomOidDefinition, ProfileOidField


class SeedProfilesTest(TestCase):

    def test_server_profile_exists_with_correct_ku(self):
        p = CertProfile.objects.get(name='server')
        self.assertTrue(p.ku_digital_signature)
        self.assertTrue(p.ku_key_encipherment)
        self.assertTrue(p.ku_key_agreement)

    def test_client_profile_exists_with_correct_ku(self):
        p = CertProfile.objects.get(name='client')
        self.assertTrue(p.ku_digital_signature)
        self.assertTrue(p.ku_key_encipherment)
        self.assertTrue(p.ku_data_encipherment)
        self.assertTrue(p.ku_key_agreement)

    def test_all_default_profiles_created(self):
        expected = {
            'server', 'client', 'server_client', 'code_signing', 'user',
            'smime_sign', 'timestamping', 'vpn', 'smartcard_logon', 'user_login',
        }
        actual = set(CertProfile.objects.values_list('name', flat=True))
        self.assertTrue(expected.issubset(actual))


class SeedOidDefinitionsTest(TestCase):

    def test_builtin_oids_created(self):
        # At minimum the built-in types should exist
        self.assertTrue(
            CustomOidDefinition.objects.filter(placement='san_dns', oid='').exists()
        )
        self.assertTrue(
            CustomOidDefinition.objects.filter(oid='1.2.643.100.3').exists()
        )

    def test_server_profile_has_dns_oid_field(self):
        server = CertProfile.objects.get(name='server')
        dns_def = CustomOidDefinition.objects.filter(placement='san_dns', oid='').first()
        self.assertIsNotNone(dns_def)
        self.assertTrue(
            ProfileOidField.objects.filter(profile=server, oid_definition=dns_def).exists()
        )

    def test_smartcard_logon_has_upn_required(self):
        sc = CertProfile.objects.get(name='smartcard_logon')
        upn_def = CustomOidDefinition.objects.filter(oid='1.3.6.1.4.1.311.20.2.3').first()
        self.assertIsNotNone(upn_def)
        link = ProfileOidField.objects.filter(profile=sc, oid_definition=upn_def).first()
        self.assertIsNotNone(link)
        self.assertTrue(link.required)
