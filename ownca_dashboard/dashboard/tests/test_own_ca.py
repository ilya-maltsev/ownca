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

"""Tests for own_ca functions.

All tests that call the openssl GOST engine are guarded with
@unittest.skipUnless(GOST_AVAILABLE, ...) so the suite stays green on CI
machines without the engine.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

from django.test import TestCase, override_settings

from dashboard import own_ca
from dashboard.own_ca import (
    CASpec, CertSpec, OwnCAError,
    create_root_ca, issue_certificate, parse_csr, parse_cert,
    revoke_certificate, generate_crl, read_crl_number,
    pkcs12_export, pem_bundle_export, cert_text,
    openssl_version, gost_engine_loaded,
    _normalize_gost_paramset, _md_for_alg, _default_md_for_cnf, _md_args,
    gost_paramset_choices,
)
from dashboard.tests.conftest import GOST_AVAILABLE


def _make_rsa_csr(subject='/CN=test.example.com', san_dns=None) -> bytes:
    tmp = Path(tempfile.mkdtemp())
    try:
        subprocess.run(
            ['openssl', 'genpkey', '-algorithm', 'RSA',
             '-pkeyopt', 'rsa_keygen_bits:2048',
             '-out', str(tmp / 'k.pem')],
            check=True, capture_output=True,
        )
        cmd = ['openssl', 'req', '-new', '-key', str(tmp / 'k.pem'),
               '-subj', subject, '-out', str(tmp / 'c.pem')]
        if san_dns:
            cnf = tmp / 'san.cnf'
            cnf.write_text(
                '[req]\ndistinguished_name=dn\nreq_extensions=v3_req\n'
                '[dn]\n[v3_req]\nsubjectAltName=@san\n[san]\n'
                + '\n'.join(f'DNS.{i+1}={d}' for i, d in enumerate(san_dns)) + '\n'
            )
            cmd += ['-config', str(cnf), '-reqexts', 'v3_req']
        subprocess.run(cmd, check=True, capture_output=True)
        return (tmp / 'c.pem').read_bytes()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class HelperFunctionsTest(TestCase):

    def test_openssl_version_returns_string(self):
        v = openssl_version()
        self.assertIsInstance(v, str)

    def test_gost_engine_loaded_returns_bool(self):
        self.assertIsInstance(gost_engine_loaded(), bool)

    def test_normalize_gost_paramset_known(self):
        # The function maps a long OID label (from openssl output) to 'A'/'B'/etc.
        # 'A' alone is not a valid OID label — use a full OID needle.
        self.assertEqual(_normalize_gost_paramset('cryptopro-a-paramset'), 'A')
        self.assertEqual(_normalize_gost_paramset('tc26-gost-3410-2012-256-paramseta'), 'A')

    def test_normalize_gost_paramset_unknown_returns_empty(self):
        # Inputs that don't match any needle return '' (not the original string)
        self.assertEqual(_normalize_gost_paramset('rsaEncryption'), '')
        self.assertEqual(_normalize_gost_paramset('unknown-param'), '')

    def test_md_for_alg_gost256(self):
        self.assertEqual(_md_for_alg('gost2012_256'), 'md_gost12_256')

    def test_md_for_alg_rsa(self):
        self.assertEqual(_md_for_alg('rsa:2048'), 'sha256')

    def test_md_for_alg_ed25519(self):
        self.assertIsNone(_md_for_alg('ed25519'))

    def test_default_md_for_cnf_ed25519(self):
        self.assertEqual(_default_md_for_cnf('ed25519'), 'default')

    def test_md_args_rsa(self):
        self.assertEqual(_md_args('rsa:2048'), ['-sha256'])

    def test_md_args_ed25519_empty(self):
        self.assertEqual(_md_args('ed25519'), [])

    def test_gost_paramset_choices_returns_list(self):
        choices = gost_paramset_choices('gost2012_256')
        self.assertIsInstance(choices, list)
        self.assertTrue(len(choices) > 0)


class ParseCsrTest(TestCase):

    def test_parse_rsa_csr_subject(self):
        csr = _make_rsa_csr('/CN=sub.test/C=RU/O=Acme')
        fields = parse_csr(csr)
        self.assertEqual(fields['common_name'], 'sub.test')
        self.assertEqual(fields['country'], 'RU')
        self.assertEqual(fields['organization'], 'Acme')

    def test_parse_csr_with_san(self):
        csr = _make_rsa_csr('/CN=san.test', san_dns=['san.test', 'www.san.test'])
        fields = parse_csr(csr)
        self.assertIn('san.test', fields['san_dns'])
        self.assertIn('www.san.test', fields['san_dns'])

    def test_parse_empty_csr_raises(self):
        with self.assertRaises(OwnCAError):
            parse_csr(b'')

    def test_parse_garbage_raises(self):
        with self.assertRaises(OwnCAError):
            parse_csr(b'not a csr at all')

    def test_raw_text_field_populated(self):
        csr = _make_rsa_csr('/CN=raw.test')
        fields = parse_csr(csr)
        self.assertIsInstance(fields['raw_text'], str)
        self.assertIn('Certificate Request', fields['raw_text'])

    def test_paramset_empty_for_rsa(self):
        csr = _make_rsa_csr('/CN=alg.test')
        fields = parse_csr(csr)
        self.assertEqual(fields['paramset'], '')


@unittest.skipUnless(GOST_AVAILABLE, 'GOST engine not available')
class CreateRootCaTest(TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix='ownca_test_root_')
        self._override = override_settings(OWNCA_STORAGE_DIR=self._tmp)
        self._override.enable()

    def tearDown(self):
        self._override.disable()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_creates_key_and_cert(self):
        ca_uuid = str(uuid.uuid4())
        create_root_ca(ca_uuid, CASpec(
            name='Test Root', subject='/CN=Test Root', key_alg='rsa:2048', days=30,
        ))
        ca_dir = Path(self._tmp) / 'cas' / ca_uuid
        self.assertTrue((ca_dir / 'ca.key').exists())
        self.assertTrue((ca_dir / 'ca.crt').exists())
        self.assertTrue((ca_dir / 'openssl.cnf').exists())

    def test_parse_cert_on_created_ca(self):
        ca_uuid = str(uuid.uuid4())
        create_root_ca(ca_uuid, CASpec(
            name='Parse CA', subject='/CN=Parse CA/O=Test',
            key_alg='rsa:2048', days=30,
        ))
        cert_path = Path(self._tmp) / 'cas' / ca_uuid / 'ca.crt'
        info = parse_cert(cert_path)
        self.assertIn('Parse CA', info.get('subject', ''))


@unittest.skipUnless(GOST_AVAILABLE, 'GOST engine not available')
class IssueCertificateTest(TestCase):

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix='ownca_test_issue_')
        self._override = override_settings(OWNCA_STORAGE_DIR=self._tmp)
        self._override.enable()
        self.ca_uuid = str(uuid.uuid4())
        create_root_ca(self.ca_uuid, CASpec(
            name='Issue Test CA', subject='/CN=Issue Test CA',
            key_alg='rsa:2048', days=30,
        ))

    def tearDown(self):
        self._override.disable()
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_issue_certificate_creates_files(self):
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='issue.test',
            subject='/CN=issue.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=[
                'basicConstraints = critical, CA:FALSE',
                'keyUsage = critical, digitalSignature',
                'subjectKeyIdentifier = hash',
                'authorityKeyIdentifier = keyid:always',
            ],
            san_dns=[],
            san_ip=[],
        )
        issue_certificate(self.ca_uuid, cert_uuid, spec)
        cert_dir = Path(self._tmp) / 'certs' / cert_uuid
        self.assertTrue((cert_dir / 'cert.pem').exists())
        self.assertTrue((cert_dir / 'key.pem').exists())
        self.assertTrue((cert_dir / 'csr.pem').exists())

    def test_issue_from_external_csr(self):
        csr = _make_rsa_csr('/CN=external.test')
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='external.test',
            subject='/CN=external.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=[
                'basicConstraints = critical, CA:FALSE',
                'keyUsage = critical, digitalSignature',
                'subjectKeyIdentifier = hash',
                'authorityKeyIdentifier = keyid:always',
            ],
            san_dns=[],
            san_ip=[],
        )
        issue_certificate(self.ca_uuid, cert_uuid, spec, csr_pem=csr)
        cert_dir = Path(self._tmp) / 'certs' / cert_uuid
        self.assertTrue((cert_dir / 'cert.pem').exists())
        self.assertFalse((cert_dir / 'key.pem').exists())

    def test_csr_extensions_do_not_leak(self):
        from dashboard.models import CertProfile
        profile = CertProfile(
            name='_strict', display_name='t',
            ku_digital_signature=True, eku='serverAuth',
        )
        hostile = _make_rsa_csr('/CN=leak.test')
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='leak.test',
            subject='/CN=leak.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=profile.to_extfile_lines(),
            san_dns=['legit.example.com'],
            san_ip=[],
        )
        issue_certificate(self.ca_uuid, cert_uuid, spec, csr_pem=hostile)
        text = cert_text(Path(self._tmp) / 'certs' / cert_uuid / 'cert.pem')
        self.assertNotIn('CA:TRUE', text)
        self.assertIn('CA:FALSE', text)

    def test_revoke_and_generate_crl(self):
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='revoke.me',
            subject='/CN=revoke.me',
            key_alg='rsa:2048',
            days=10,
            ext_lines=[
                'basicConstraints = critical, CA:FALSE',
                'keyUsage = critical, digitalSignature',
                'subjectKeyIdentifier = hash',
                'authorityKeyIdentifier = keyid:always',
            ],
            san_dns=[],
            san_ip=[],
        )
        issue_certificate(self.ca_uuid, cert_uuid, spec)
        revoke_certificate(self.ca_uuid, cert_uuid, reason='keyCompromise')
        generate_crl(self.ca_uuid)
        crl_path = Path(self._tmp) / 'cas' / self.ca_uuid / 'crl.pem'
        self.assertTrue(crl_path.exists())

    def test_read_crl_number_returns_string(self):
        generate_crl(self.ca_uuid)
        num = read_crl_number(self.ca_uuid)
        self.assertIsInstance(num, str)

    def test_pkcs12_export(self):
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='p12.test',
            subject='/CN=p12.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=[
                'basicConstraints = critical, CA:FALSE',
                'keyUsage = critical, digitalSignature',
                'subjectKeyIdentifier = hash',
                'authorityKeyIdentifier = keyid:always',
            ],
            san_dns=[],
            san_ip=[],
        )
        issue_certificate(self.ca_uuid, cert_uuid, spec)
        ca_cert_path = Path(self._tmp) / 'cas' / self.ca_uuid / 'ca.crt'
        data = pkcs12_export(cert_uuid, [ca_cert_path], 'testpass')
        self.assertIsInstance(data, bytes)
        self.assertTrue(len(data) > 0)

    def test_pkcs12_export_tk26(self):
        # GOST cert + gostkeybag=True → gost-engine should produce
        # an RFC 9337/9548 PFX. Class-level @skipUnless(GOST_AVAILABLE)
        # already gates this on the engine being present.
        ca_uuid = str(uuid.uuid4())
        create_root_ca(ca_uuid, CASpec(
            name='TK-26 CA', subject='/CN=TK-26 CA',
            key_alg='gost2012_256', days=30,
        ))
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='tk26.test',
            subject='/CN=tk26.test',
            key_alg='gost2012_256',
            paramset='A',
            days=10,
            ext_lines=[
                'basicConstraints = critical, CA:FALSE',
                'keyUsage = critical, digitalSignature',
                'subjectKeyIdentifier = hash',
                'authorityKeyIdentifier = keyid:always',
            ],
            san_dns=[],
            san_ip=[],
        )
        issue_certificate(ca_uuid, cert_uuid, spec)
        ca_cert_path = Path(self._tmp) / 'cas' / ca_uuid / 'ca.crt'
        data = pkcs12_export(
            cert_uuid, [ca_cert_path], 'testpass',
            gostkeybag=True,
            keybag_cipher='kuznyechik-ctr-acpkm',
            certbag_cipher='kuznyechik-ctr-acpkm',
        )
        self.assertIsInstance(data, bytes)
        self.assertGreater(len(data), 0)

    def test_pem_bundle_export(self):
        cert_uuid = str(uuid.uuid4())
        spec = CertSpec(
            common_name='bundle.test',
            subject='/CN=bundle.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=[
                'basicConstraints = critical, CA:FALSE',
                'keyUsage = critical, digitalSignature',
                'subjectKeyIdentifier = hash',
                'authorityKeyIdentifier = keyid:always',
            ],
            san_dns=[],
            san_ip=[],
        )
        issue_certificate(self.ca_uuid, cert_uuid, spec)
        ca_cert_path = Path(self._tmp) / 'cas' / self.ca_uuid / 'ca.crt'
        bundle = pem_bundle_export(cert_uuid, [ca_cert_path])
        self.assertIn(b'BEGIN CERTIFICATE', bundle)
