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

"""Tests for model methods:
CertProfile.to_extfile_lines, get_san_custom, ku_display, ku_openssl_names,
CertProfile.is_ca_profile gate, ProfileOidField.normalised_value,
CertificateAuthority.__str__, Certificate.__str__,
UserProfile.role, UserProfile.get_available_cas, UserProfile.cidr_list,
SystemSettings.get_solo."""
from __future__ import annotations

import uuid

from django.contrib.auth.models import Group, User
from django.test import TestCase

from dashboard.models import (
    ASN1_TYPE_MAP,
    CertProfile,
    CertificateAuthority,
    Certificate,
    CustomOidDefinition,
    ProfileOidField,
    SystemSettings,
    UserProfile,
)


class CertProfileExtfileTest(TestCase):

    def test_server_profile_produces_correct_lines(self):
        p = CertProfile(
            name='_t', display_name='t',
            ku_digital_signature=True,
            ku_key_encipherment=True,
            ku_key_agreement=True,
            eku='serverAuth',
        )
        lines = p.to_extfile_lines()
        joined = '\n'.join(lines)
        self.assertIn('basicConstraints = critical, CA:FALSE', lines)
        self.assertIn('digitalSignature', joined)
        self.assertIn('keyEncipherment', joined)
        self.assertIn('keyAgreement', joined)
        self.assertIn('extendedKeyUsage = serverAuth', joined)

    def test_no_ku_bits_emits_no_ku_line(self):
        p = CertProfile(name='_t_empty', display_name='t')
        for line in p.to_extfile_lines():
            self.assertFalse(line.startswith('keyUsage'))

    def test_ca_profile_emits_ca_true(self):
        p = CertProfile(name='_t_ca', display_name='t', is_ca_profile=True)
        self.assertIn('basicConstraints = critical, CA:TRUE', p.to_extfile_lines())

    def test_eku_critical_flag(self):
        p = CertProfile(name='_t', display_name='t', eku='timeStamping', eku_critical=True)
        joined = '\n'.join(p.to_extfile_lines())
        self.assertIn('extendedKeyUsage = critical, timeStamping', joined)

    def test_name_constraints_emitted(self):
        p = CertProfile(
            name='_t_nc', display_name='t',
            name_constraints_permitted='DNS:.example.org',
            name_constraints_critical=True,
        )
        joined = '\n'.join(p.to_extfile_lines())
        self.assertIn('nameConstraints', joined)
        self.assertIn('.example.org', joined)

    def test_policy_constraints_emitted(self):
        p = CertProfile(
            name='_t_pc', display_name='t',
            policy_constraints_require_explicit=0,
        )
        joined = '\n'.join(p.to_extfile_lines())
        self.assertIn('policyConstraints', joined)

    def test_inhibit_any_policy_emitted(self):
        p = CertProfile(name='_t_iap', display_name='t', inhibit_any_policy=2)
        joined = '\n'.join(p.to_extfile_lines())
        self.assertIn('inhibitAnyPolicy', joined)

    def test_extra_extensions_appended(self):
        p = CertProfile(name='_t_ext', display_name='t',
                        extra_extensions='tlsfeature = status_request')
        self.assertIn('tlsfeature = status_request', p.to_extfile_lines())


class CertProfileKuDisplayTest(TestCase):

    def test_ku_display_non_empty(self):
        p = CertProfile(name='_t', display_name='t', ku_digital_signature=True)
        self.assertIn('dS', p.ku_display)

    def test_ku_display_none_when_empty(self):
        p = CertProfile(name='_t2', display_name='t2')
        self.assertEqual(p.ku_display, '(none)')

    def test_ku_openssl_names(self):
        p = CertProfile(
            name='_t3', display_name='t',
            ku_digital_signature=True,
            ku_key_encipherment=True,
        )
        names = p.ku_openssl_names
        self.assertIn('digitalSignature', names)
        self.assertIn('keyEncipherment', names)


class CertProfileOidFieldsTest(TestCase):

    def setUp(self):
        self.profile = CertProfile.objects.create(
            name='_oid_test', display_name='OID Test',
        )
        self.oid_def = CustomOidDefinition.objects.create(
            oid='1.2.3.4.5',
            label='Test OID',
            asn1_type='UTF8',
            placement='extension',
        )
        ProfileOidField.objects.create(
            profile=self.profile,
            oid_definition=self.oid_def,
            order=0,
        )

    def test_to_extfile_lines_includes_oid_value(self):
        lines = self.profile.to_extfile_lines({'1.2.3.4.5': 'hello'})
        self.assertTrue(any('1.2.3.4.5' in l and 'hello' in l for l in lines))

    def test_get_san_custom_dns(self):
        dns_def = CustomOidDefinition.objects.create(
            oid='', label='DNS', asn1_type='IA5', placement='san_dns',
        )
        ProfileOidField.objects.create(
            profile=self.profile, oid_definition=dns_def, order=1,
        )
        result = self.profile.get_san_custom({'san_dns': 'a.example.com,b.example.com'})
        self.assertIn('a.example.com', result['dns'])
        self.assertIn('b.example.com', result['dns'])


class CertificateAuthorityStrTest(TestCase):

    def test_str_returns_name(self):
        ca = CertificateAuthority(name='My CA')
        self.assertEqual(str(ca), 'My CA')


class CertificateStrTest(TestCase):

    def test_str_returns_cn_and_serial(self):
        cert = Certificate(common_name='test.example.com', serial_hex='ABCD')
        self.assertEqual(str(cert), 'test.example.com (ABCD)')


class UserProfileRoleTest(TestCase):

    def setUp(self):
        self.user = User.objects.create_user('roletest', password='pw')
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)

    def test_role_none_when_no_group(self):
        self.assertEqual(self.profile.role, 'none')

    def test_role_admin_when_in_admins_group(self):
        grp, _ = Group.objects.get_or_create(name='admins')
        self.user.groups.add(grp)
        self.assertEqual(self.profile.role, 'admin')

    def test_role_operator_when_in_operators_group(self):
        grp, _ = Group.objects.get_or_create(name='operators')
        self.user.groups.add(grp)
        self.assertEqual(self.profile.role, 'operator')

    def test_cidr_list_empty_when_blank(self):
        self.profile.allowed_cidrs = ''
        self.assertEqual(self.profile.cidr_list(), [])

    def test_cidr_list_parses_entries(self):
        self.profile.allowed_cidrs = '10.0.0.0/8\n192.168.1.0/24'
        self.assertIn('10.0.0.0/8', self.profile.cidr_list())


class SystemSettingsTest(TestCase):

    def test_get_solo_creates_singleton(self):
        s = SystemSettings.get_solo()
        self.assertIsNotNone(s)

    def test_get_solo_idempotent(self):
        s1 = SystemSettings.get_solo()
        s2 = SystemSettings.get_solo()
        self.assertEqual(s1.pk, s2.pk)
