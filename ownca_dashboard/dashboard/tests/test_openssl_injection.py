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

"""openssl config injection through certificate field values.

openssl expands ``${ENV::NAME}`` inside an extfile value, so an unescaped OID
field could copy a secret from the process environment into a signed
certificate; ``#`` cut the value short and a line break appended config lines
of the sender's choosing. Each test signs for real and reads the certificate
back, or drives the view with a hand-crafted POST the form would not send.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from unittest import mock

from django.urls import reverse

from dashboard import own_ca
from dashboard.models import (
    Certificate, CustomOidDefinition, ProfileOidField, SystemSettings,
)
from dashboard.tests.conftest import CATestCase

TEST_OID = '1.2.3.9901'
INJECTION = ('ok\nbasicConstraints = critical, CA:TRUE\n'
             'keyUsage = critical, keyCertSign, cRLSign')


def _cert_der(cert_uuid) -> bytes:
    """DER of the signed certificate. A UTF8String value sits in it verbatim,
    so a byte search is enough to tell what openssl actually signed."""
    pem = (own_ca._storage_root() / 'certs' / str(cert_uuid) / 'cert.pem').read_bytes()
    return own_ca._pem_to_der(pem)


class OpensslConfigInjectionTest(CATestCase):

    def setUp(self):
        super().setUp()
        s = SystemSettings.get_solo()
        s.disable_cert_profile_protection = True
        s.allow_server_key_generation = True
        s.save()
        oid = CustomOidDefinition.objects.create(
            oid=TEST_OID, label='Sec OID', asn1_type='UTF8',
            placement='extension')
        ProfileOidField.objects.create(profile=self.profile,
                                       oid_definition=oid, order=1)

    def _issue(self, cn='host.test.local', **extra):
        data = {'ca': str(self.ca.uuid), 'cert_profile': str(self.profile.pk),
                'common_name': cn, 'key_alg': 'rsa:2048', 'days': '1'}
        data.update(extra)
        return self.client.post(reverse('custom_cert_issue'), data, follow=True)

    def _issued(self, cn='host.test.local'):
        return Certificate.objects.get(common_name=cn)

    def test_newline_in_an_oid_value_is_refused_by_the_issue_view(self):
        resp = self._issue(**{f'custom_oid_{TEST_OID}': INJECTION})
        self.assertContains(resp, 'must be a single line')
        self.assertFalse(Certificate.objects.exists())

    def test_newline_in_a_free_form_oid_row_is_refused(self):
        resp = self._issue(cert_profile='', oid_row_oid_0=TEST_OID,
                           oid_row_type_0='UTF8', oid_row_value_0=INJECTION)
        self.assertContains(resp, 'line break')
        self.assertFalse(Certificate.objects.exists())

    def test_an_environment_reference_is_signed_literally_not_expanded(self):
        with mock.patch.dict(os.environ, {'OWNCA_SECTEST_SECRET': 'leaked-secret'}):
            self._issue(**{f'custom_oid_{TEST_OID}': '${ENV::OWNCA_SECTEST_SECRET}'})
        value = _cert_der(self._issued().uuid)
        self.assertNotIn(b'leaked-secret', value)
        self.assertIn(b'${ENV::OWNCA_SECTEST_SECRET}', value)

    def test_a_free_form_oid_row_is_signed_literally_not_expanded(self):
        with mock.patch.dict(os.environ, {'OWNCA_SECTEST_SECRET': 'leaked-secret'}):
            self._issue(cert_profile='', oid_row_oid_0=TEST_OID,
                        oid_row_type_0='UTF8',
                        oid_row_value_0='${ENV::OWNCA_SECTEST_SECRET}')
        value = _cert_der(self._issued().uuid)
        self.assertNotIn(b'leaked-secret', value)
        self.assertIn(b'${ENV::OWNCA_SECTEST_SECRET}', value)

    def test_comment_and_quote_characters_survive_signing(self):
        raw = 'a#b "c" \'d\' e\\f'
        self._issue(**{f'custom_oid_{TEST_OID}': raw})
        self.assertIn(raw.encode(), _cert_der(self._issued().uuid))

    def test_the_signer_refuses_a_multiline_line_from_any_channel(self):
        # Renewal re-renders stored custom_oid_values, so a value saved before
        # the view check must still never reach openssl as two lines.
        for field, value in (
            ('ext_lines', ['basicConstraints = critical, CA:FALSE',
                           f'{TEST_OID} = ASN1:UTF8String:{INJECTION}']),
            ('san_dns', ['ok.test\nbasicConstraints = critical, CA:TRUE']),
            ('san_other', ['1.3.6.1.4.1.311.20.2.3;UTF8String:a\rb']),
        ):
            spec = own_ca.CertSpec(
                common_name='core.test', subject='/CN=core.test',
                key_alg='rsa:2048', days=1,
                ext_lines=['basicConstraints = critical, CA:FALSE'],
                san_dns=[], san_ip=[])
            setattr(spec, field, value)
            cert_uuid = str(uuid.uuid4())
            with self.subTest(field=field):
                with self.assertRaises(own_ca.OwnCAError):
                    own_ca.issue_certificate(self.ca_uuid, cert_uuid, spec)
                self.assertFalse(
                    (Path(self._tmp) / 'certs' / cert_uuid / 'cert.pem').exists())

    def test_the_intermediate_extfile_refuses_a_multiline_line(self):
        spec = own_ca.CASpec(name='Sub', subject='/CN=Sub', key_alg='rsa:2048',
                             days=1, crl_url='http://x/crl\nbasicConstraints = CA:FALSE')
        with self.assertRaises(own_ca.OwnCAError):
            own_ca._build_intermediate_extfile(Path(self._tmp), spec)

    def test_a_machine_account_upn_with_a_dollar_sign_is_signed_verbatim(self):
        spec = own_ca.CertSpec(
            common_name='ws01', subject='/CN=ws01', key_alg='rsa:2048', days=1,
            ext_lines=['basicConstraints = critical, CA:FALSE'],
            san_dns=[], san_ip=[],
            san_other=['1.3.6.1.4.1.311.20.2.3;UTF8String:ws01$@test.local'])
        cert_uuid = str(uuid.uuid4())
        own_ca.issue_certificate(self.ca_uuid, cert_uuid, spec)
        self.assertIn(b'ws01$@test.local', _cert_der(cert_uuid))
