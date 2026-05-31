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

"""Tests for certificate views: certificates_view, csr_parse_view,
cert_detail_view, cert_download_view, cert_renew_view, cert_revoke_view,
cert_delete_view."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

from django.test import override_settings
from django.urls import reverse

from dashboard import own_ca
from dashboard.own_ca import CASpec, CertSpec
from dashboard.models import Certificate, CertificateAuthority
from dashboard.tests.conftest import DashboardTestCase, GOST_AVAILABLE, make_cert_profile


class CertificatesListTest(DashboardTestCase):

    def test_list_renders(self):
        resp = self.client.get(reverse('certificates'))
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'dashboard/certificates.html')


class CsrParseViewTest(DashboardTestCase):

    def _make_rsa_csr(self) -> bytes:
        tmp = Path(tempfile.mkdtemp())
        try:
            subprocess.run(
                ['openssl', 'genpkey', '-algorithm', 'RSA',
                 '-pkeyopt', 'rsa_keygen_bits:2048',
                 '-out', str(tmp / 'k.pem')],
                check=True, capture_output=True,
            )
            subprocess.run(
                ['openssl', 'req', '-new',
                 '-key', str(tmp / 'k.pem'),
                 '-subj', '/CN=parse.test/O=Test',
                 '-out', str(tmp / 'c.pem')],
                check=True, capture_output=True,
            )
            return (tmp / 'c.pem').read_bytes()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_post_returns_405_for_get(self):
        resp = self.client.get(reverse('csr_parse'))
        self.assertEqual(resp.status_code, 405)

    def test_post_without_csr_returns_400(self):
        resp = self.client.post(reverse('csr_parse'), {})
        self.assertEqual(resp.status_code, 400)
        data = json.loads(resp.content)
        self.assertIn('error', data)

    def test_post_with_text_csr_returns_fields(self):
        csr_pem = self._make_rsa_csr()
        resp = self.client.post(
            reverse('csr_parse'),
            {'csr_text': csr_pem.decode()},
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertTrue(data['ok'])
        self.assertEqual(data['fields']['common_name'], 'parse.test')

    def test_post_with_invalid_csr_returns_400(self):
        resp = self.client.post(reverse('csr_parse'), {'csr_text': 'not a csr'})
        self.assertEqual(resp.status_code, 400)


@unittest.skipUnless(GOST_AVAILABLE, 'GOST engine not available')
class CertDetailViewTest(DashboardTestCase):

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix='ownca_test_cert_')
        self._override = override_settings(OWNCA_STORAGE_DIR=self._tmp)
        self._override.enable()

        ca_uuid = str(uuid.uuid4())
        own_ca.create_root_ca(ca_uuid, CASpec(
            name='Cert Detail CA',
            subject='/CN=Cert Detail CA',
            key_alg='rsa:2048',
            days=30,
        ))
        self.ca = CertificateAuthority.objects.create(
            uuid=ca_uuid,
            name='Cert Detail CA',
            ca_type='root',
            subject='/CN=Cert Detail CA',
            key_alg='rsa:2048',
        )
        self.profile = make_cert_profile()

        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='detail.test',
            subject='/CN=detail.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=self.profile.to_extfile_lines(),
            san_dns=[],
            san_ip=[],
        )
        info = own_ca.issue_certificate(ca_uuid, cert_uuid, spec)
        self.cert = Certificate.objects.create(
            uuid=cert_uuid,
            common_name='detail.test',
            subject='/CN=detail.test',
            issuer_ca=self.ca,
            cert_profile=self.profile,
            key_alg='rsa:2048',
            serial_hex=info.get('serial_hex', ''),
            has_private_key=True,
        )

    def tearDown(self):
        self._override.disable()
        shutil.rmtree(self._tmp, ignore_errors=True)
        super().tearDown()

    def test_cert_detail_renders(self):
        resp = self.client.get(reverse('cert_detail', args=[self.cert.uuid]))
        self.assertEqual(resp.status_code, 200)

    def test_cert_detail_unknown_404(self):
        resp = self.client.get(reverse('cert_detail', args=[uuid.uuid4()]))
        self.assertEqual(resp.status_code, 404)

    def test_cert_download_pem(self):
        resp = self.client.get(reverse('cert_download', args=[self.cert.uuid, 'cert']))
        self.assertEqual(resp.status_code, 200)

    def test_cert_download_key(self):
        resp = self.client.get(reverse('cert_download', args=[self.cert.uuid, 'key']))
        self.assertEqual(resp.status_code, 200)

    def test_cert_download_bundle(self):
        resp = self.client.get(reverse('cert_download', args=[self.cert.uuid, 'bundle']))
        self.assertEqual(resp.status_code, 200)

    def test_cert_download_p12_post(self):
        resp = self.client.post(
            reverse('cert_download', args=[self.cert.uuid, 'p12']),
            {'password': 'testpass'},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/x-pkcs12')

    def test_cert_download_p12_requires_passphrase(self):
        resp = self.client.post(
            reverse('cert_download', args=[self.cert.uuid, 'p12']),
            {'password': ''},
        )
        self.assertRedirects(
            resp, reverse('cert_detail', args=[self.cert.uuid]),
            fetch_redirect_response=False,
        )

    def test_cert_download_p12_gostkeybag_rejects_rsa(self):
        # The TK-26 checkbox is GOST-only; submitting it for an RSA cert
        # must redirect with an error rather than producing a broken file.
        resp = self.client.post(
            reverse('cert_download', args=[self.cert.uuid, 'p12']),
            {'password': 'testpass', 'gostkeybag': '1'},
        )
        self.assertRedirects(
            resp, reverse('cert_detail', args=[self.cert.uuid]),
            fetch_redirect_response=False,
        )

    def test_cert_renew_creates_new_cert(self):
        before = Certificate.objects.count()
        self.client.post(
            reverse('cert_renew', args=[self.cert.uuid]),
            {'days': '10'},
        )
        self.assertEqual(Certificate.objects.count(), before + 1)

    def test_cert_revoke_marks_revoked(self):
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='revoke.test',
            subject='/CN=revoke.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=self.profile.to_extfile_lines(),
            san_dns=[],
            san_ip=[],
        )
        own_ca.issue_certificate(str(self.ca.uuid), cert_uuid, spec)
        cert = Certificate.objects.create(
            uuid=cert_uuid,
            common_name='revoke.test',
            subject='/CN=revoke.test',
            issuer_ca=self.ca,
            key_alg='rsa:2048',
        )
        self.client.post(
            reverse('cert_revoke', args=[cert.uuid]),
            {'reason': 'keyCompromise'},
        )
        cert.refresh_from_db()
        self.assertEqual(cert.status, 'revoked')
        self.assertEqual(cert.revocation_reason, 'keyCompromise')
