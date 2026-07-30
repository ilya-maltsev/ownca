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
"""
Unit tests for the CryptoPro CSP integration that DO NOT require CryptoPro to be
installed — they cover the pure Python logic (gating, gamma format/accounting,
license precedence, own_ca backend routing helpers) plus the management page.
The live crypto path (container keygen + self-sign) is exercised separately in a
CryptoPro-enabled image; see plans_dashboard/cryptopro_csp/.
"""
from __future__ import annotations

import re
import tempfile
import uuid
import zlib
from pathlib import Path
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from dashboard import cryptopro, own_ca
from dashboard.own_ca import CertSpec
from dashboard.models import Certificate, CertificateAuthority, CryptoProSettings
from dashboard.tests.conftest import CATestCase


class GammaFormatTest(TestCase):
    def test_segment_geometry(self):
        self.assertEqual(cryptopro.GAMMA_SEGMENT_LEN, 36)
        self.assertEqual(cryptopro.GAMMA_BYTES_PER_KEY, 36)

    def test_segment_appends_crc32_le(self):
        data = b'\x11' * 32
        seg = cryptopro._segment(data)
        self.assertEqual(len(seg), 36)
        self.assertEqual(seg[:32], data)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        self.assertEqual(seg[32:], crc.to_bytes(4, 'little'))

    def test_format_raw_drops_partial_tail(self):
        # 32*3 + 5 leftover bytes -> only 3 full segments
        pool = cryptopro.format_raw_gamma(b'\x00' * (32 * 3 + 5))
        self.assertEqual(len(pool), 36 * 3)
        self.assertEqual(cryptopro.validate_pool(pool), 3)

    def test_generate_gamma_count(self):
        pool = cryptopro.generate_gamma(7)
        self.assertEqual(len(pool), 36 * 7)
        self.assertEqual(cryptopro.validate_pool(pool), 7)

    def test_validate_rejects_bad_length(self):
        with self.assertRaises(cryptopro.CryptoProError):
            cryptopro.validate_pool(b'\x00' * 35)

    def test_validate_rejects_bad_crc(self):
        with self.assertRaises(cryptopro.CryptoProError):
            cryptopro.validate_pool(b'\x00' * 36)  # CRC of 32 zero bytes != 0

    def test_generate_gamma_rejects_nonpositive(self):
        with self.assertRaises(cryptopro.CryptoProError):
            cryptopro.generate_gamma(0)


class GammaAccountingTest(TestCase):
    def _with_gamma_dir(self):
        d = tempfile.mkdtemp()
        return override_settings(OWNCA_CRYPTOPRO_GAMMA_DIR=d), d

    def test_write_and_count_roundtrip(self):
        ctx, _d = self._with_gamma_dir()
        with ctx:
            cryptopro.write_gamma(cryptopro.generate_gamma(5), mode='replace')
            st = cryptopro.gamma_status()
            self.assertEqual(st.draws_remaining, 5)
            self.assertTrue(st.ok)
            # append 3 more -> 8
            cryptopro.write_gamma(cryptopro.generate_gamma(3), mode='append')
            self.assertEqual(cryptopro.gamma_status().draws_remaining, 8)

    def test_ingest_raw_upload(self):
        ctx, _d = self._with_gamma_dir()
        with ctx:
            n = cryptopro.ingest_upload(b'\x00' * (32 * 4), raw=True, mode='replace')
            self.assertEqual(n, 4)
            self.assertEqual(cryptopro.gamma_status().draws_remaining, 4)

    def test_empty_dir_zero_draws(self):
        ctx, _d = self._with_gamma_dir()
        with ctx:
            st = cryptopro.gamma_status()
            self.assertEqual(st.draws_remaining, 0)
            self.assertFalse(st.ok)


class GatingTest(TestCase):
    def test_unavailable_without_marker(self):
        with override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker'):
            self.assertFalse(cryptopro.available())
            self.assertFalse(cryptopro.enabled())

    def test_enabled_requires_both(self):
        with tempfile.NamedTemporaryFile() as marker:
            # marker present but runtime flag off -> not enabled
            with override_settings(OWNCA_CRYPTOPRO_MARKER=marker.name,
                                   OWNCA_CRYPTOPRO_ENABLED=False):
                self.assertTrue(cryptopro.available())
                self.assertFalse(cryptopro.enabled())
            # both on -> enabled
            with override_settings(OWNCA_CRYPTOPRO_MARKER=marker.name,
                                   OWNCA_CRYPTOPRO_ENABLED=True):
                self.assertTrue(cryptopro.enabled())

    def test_status_unavailable_never_raises(self):
        with override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker'):
            info = cryptopro.status()
            self.assertFalse(info.available)
            self.assertEqual(info.providers, [])


class LicensePrecedenceTest(TestCase):
    def test_demo_when_unset(self):
        CryptoProSettings.objects.all().delete()
        with override_settings(OWNCA_CRYPTOPRO_LICENSE=''):
            serial, source = cryptopro.effective_license_serial()
            self.assertEqual(serial, '')
            self.assertEqual(source, 'demo')

    def test_env_used_when_no_ui(self):
        CryptoProSettings.objects.all().delete()
        with override_settings(OWNCA_CRYPTOPRO_LICENSE='ENV12-XXXXX'):
            serial, source = cryptopro.effective_license_serial()
            self.assertEqual(serial, 'ENV12-XXXXX')
            self.assertEqual(source, 'env')

    def test_ui_overrides_env(self):
        cps = CryptoProSettings.get_solo()
        cps.license_serial = 'UI999-YYYYY'
        cps.save()
        with override_settings(OWNCA_CRYPTOPRO_LICENSE='ENV12-XXXXX'):
            serial, source = cryptopro.effective_license_serial()
            self.assertEqual(serial, 'UI999-YYYYY')
            self.assertEqual(source, 'ui')


class OwnCaBackendHelpersTest(TestCase):
    def test_subject_openssl_to_x500(self):
        self.assertEqual(
            own_ca._openssl_subj_to_x500('/C=RU/O=Org/CN=Name'),
            'C=RU, O=Org, CN=Name',
        )
        # already comma form -> unchanged
        self.assertEqual(own_ca._openssl_subj_to_x500('CN=Name'), 'CN=Name')

    def test_container_name_is_hdimage_safe(self):
        u = uuid.uuid4()
        name = own_ca._capi_container_for(str(u))
        self.assertTrue(name.startswith('ownca_ca_'))
        self.assertNotIn('-', name)

    def test_cryptopro_not_active_for_non_gost(self):
        self.assertFalse(own_ca._cryptopro_active_for('rsa:2048'))
        self.assertFalse(own_ca._cryptopro_active_for('ec:P-256'))

    def test_read_ca_backend_roundtrip(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            ca_uuid = str(uuid.uuid4())
            ca_dir = Path(d) / 'cas' / ca_uuid
            ca_dir.mkdir(parents=True)
            # no marker -> openssl
            self.assertEqual(own_ca.read_ca_backend(ca_uuid), ('openssl', ''))
            own_ca._write_backend(ca_dir, 'capilite:ownca_ca_abc')
            self.assertEqual(own_ca.read_ca_backend(ca_uuid), ('capilite', 'ownca_ca_abc'))



class ExtspecBuilderTest(TestCase):
    """Pure extspec-builder logic (own_ca) — the structured extension data the
    CAPILite shim consumes. No CryptoPro needed."""

    def test_ku_hex_unused_cert_sign_crl_sign(self):
        # keyCertSign (0x04) + cRLSign (0x02) => 0x06, last set bit is bit6 => 1 unused
        self.assertEqual(own_ca._ku_hex_unused(['keyCertSign', 'cRLSign']), ('06', 1))

    def test_ku_hex_unused_digsig_keyenc(self):
        # digitalSignature (0x80) + keyEncipherment (0x20) => 0xa0, bit2 last => 5 unused
        self.assertEqual(own_ca._ku_hex_unused(['digitalSignature', 'keyEncipherment']), ('a0', 5))

    def test_eku_name_and_raw_oid(self):
        self.assertEqual(
            own_ca._eku_to_oids(['serverAuth', '1.2.3.4']),
            ['1.3.6.1.5.5.7.3.1', '1.2.3.4'],
        )

    def test_ip_to_hex_v4(self):
        self.assertEqual(own_ca._ip_to_hex('10.0.0.9'), '0a000009')
        self.assertEqual(own_ca._ip_to_hex('not-an-ip'), '')

    def test_parse_profile_ext_lines(self):
        prof = own_ca._parse_profile_ext_lines([
            'basicConstraints = critical, CA:FALSE',
            'keyUsage = critical, digitalSignature, keyEncipherment',
            'extendedKeyUsage = serverAuth, clientAuth',
        ])
        self.assertFalse(prof['bc_ca'])
        self.assertTrue(prof['ku_critical'])
        self.assertEqual(prof['ku'], ['digitalSignature', 'keyEncipherment'])
        self.assertEqual(prof['eku'], ['serverAuth', 'clientAuth'])

    def test_parse_profile_ca_pathlen(self):
        prof = own_ca._parse_profile_ext_lines(['basicConstraints = critical, CA:TRUE, pathlen:2'])
        self.assertTrue(prof['bc_ca'])
        self.assertEqual(prof['bc_pathlen'], 2)

    def test_write_extspec_roundtrip(self):
        import tempfile, os
        d = tempfile.mkdtemp()
        p = own_ca.Path(d) / 'ext.txt'
        own_ca._write_extspec(
            p, is_ca=False, pathlen=-1,
            ku=['digitalSignature'], ku_critical=True,
            eku=['serverAuth'], eku_critical=False,
            san_dns=['a.example'], san_ip=['10.0.0.1'],
            cdp='http://x/crl', aia_ca='http://x/ca', aia_ocsp='http://x/ocsp',
        )
        text = p.read_text()
        self.assertIn('bc_ca=0', text)
        self.assertIn('ku_hex=80', text)
        self.assertIn('eku=1.3.6.1.5.5.7.3.1', text)
        self.assertIn('san_dns=a.example', text)
        self.assertIn('san_ip=0a000001', text)
        self.assertIn('cdp=http://x/crl', text)
        self.assertIn('ski=1', text)


class CapiliteSpecRejectTest(TestCase):
    """_reject_unsupported_spec_capilite — a profile carrying extensions the
    shim cannot encode must fail loudly, never silently drop them."""

    def _spec(self, **kw):
        base = dict(common_name='x', subject='/CN=x', key_alg='gost2012_256',
                    days=1, ext_lines=['basicConstraints = critical, CA:FALSE'],
                    san_dns=[], san_ip=[])
        base.update(kw)
        return own_ca.CertSpec(**base)

    def test_supported_spec_passes(self):
        own_ca._reject_unsupported_spec_capilite(self._spec(ext_lines=[
            'basicConstraints = critical, CA:FALSE',
            'keyUsage = critical, digitalSignature',
            'extendedKeyUsage = serverAuth',
            'subjectKeyIdentifier = hash',
            'authorityKeyIdentifier = keyid:always',
        ]))  # no raise

    def test_rejects_name_constraints_line(self):
        with self.assertRaisesRegex(own_ca.OwnCAError, 'nameconstraints'):
            own_ca._reject_unsupported_spec_capilite(self._spec(ext_lines=[
                'nameConstraints = critical, permitted;DNS:.example.org',
            ]))

    def test_rejects_raw_oid_extension_line(self):
        with self.assertRaisesRegex(own_ca.OwnCAError, '1.2.643.100.1'):
            own_ca._reject_unsupported_spec_capilite(self._spec(ext_lines=[
                '1.2.643.100.1 = ASN1:NUMERICSTRING:1027700132195',
            ]))

    def test_rejects_other_name_san(self):
        with self.assertRaisesRegex(own_ca.OwnCAError, 'otherName'):
            own_ca._reject_unsupported_spec_capilite(
                self._spec(san_other=['1.2.3;UTF8:x']))

    def test_sia_freshest_crl_and_issuer_alt_name_are_accepted(self):
        """These used to be refused; the shim now encodes all three, so a spec
        carrying them must pass through instead of failing."""
        own_ca._reject_unsupported_spec_capilite(self._spec(
            sia_url='http://x/repo',
            freshest_crl_url='http://x/delta.crl',
            issuer_alt_names=['email:ca@x.ru', 'URI:http://ca.x.ru'],
        ))  # no raise

    def test_rejects_issuer_alt_name_of_an_unencodable_type(self):
        with self.assertRaisesRegex(own_ca.OwnCAError, 'dirName'):
            own_ca._reject_unsupported_spec_capilite(
                self._spec(issuer_alt_names=['dirName:sec']))

    def test_error_lists_all_offenders_once(self):
        try:
            own_ca._reject_unsupported_spec_capilite(self._spec(
                san_other=['1.2.3;UTF8:x'], ext_lines=[
                    'nameConstraints = permitted;DNS:.a',
                    'nameConstraints = excluded;DNS:.b',
                ]))
            self.fail('expected OwnCAError')
        except own_ca.OwnCAError as e:
            msg = str(e)
            self.assertIn('otherName', msg)
            # deduplicated: 'nameconstraints' appears once
            self.assertEqual(msg.count('nameconstraints'), 1)


class CapiliteRenewRoutingTest(TestCase):
    """Renew on a capilite CA routes by what the old cert left on disk:
    container marker -> re-issue from the same container; csr.pem -> issuecsr;
    neither -> clear error. Shim calls are intercepted."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        self.calls = []

    def _prep_ca(self, root):
        ca_dir = Path(root) / 'cas' / self.ca_uuid
        ca_dir.mkdir(parents=True)
        (ca_dir / 'ca.crt').write_text('stub')
        own_ca._write_backend(ca_dir, 'capilite:ownca_ca_test')
        (ca_dir / 'subject_x500').write_text('C=RU, O=T, CN=Root\n')
        (ca_dir / 'key_alg').write_text('gost2012_256\n')
        return ca_dir

    def _spec(self):
        return own_ca.CertSpec(
            common_name='r', subject='/CN=r', key_alg='gost2012_256', days=30,
            ext_lines=['basicConstraints = critical, CA:FALSE'],
            san_dns=[], san_ip=[])

    def _fake_run_capi(self, args):
        self.calls.append(args)
        # produce a syntactically-valid DER file for the --out target
        for i, a in enumerate(args):
            if a == '--out':
                Path(args[i + 1]).write_bytes(b'\x30\x03\x02\x01\x01')
        return '{"ok":true}'

    def test_renew_from_container(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            self._prep_ca(self.d)
            old_u, new_u = str(uuid.uuid4()), str(uuid.uuid4())
            old_dir = Path(self.d) / 'certs' / old_u
            old_dir.mkdir(parents=True)
            (old_dir / 'container').write_text('ownca_crt_old\n')
            (old_dir / 'subject_x500').write_text('C=RU, CN=leaf\n')
            (old_dir / 'key_alg').write_text('gost2012_256\n')
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, 'parse_cert',
                                   return_value={'subject': 'C=RU, CN=leaf'}):
                info = own_ca.renew_certificate(
                    self.ca_uuid, old_u, new_u, self._spec())
            self.assertTrue(info['has_private_key'])
            cmd = self.calls[0]
            self.assertEqual(cmd[0], 'issue')
            self.assertIn('ownca_crt_old', cmd)       # SAME container reused
            new_dir = Path(self.d) / 'certs' / new_u
            self.assertEqual((new_dir / 'container').read_text().strip(),
                             'ownca_crt_old')

    def test_renew_from_csr(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            self._prep_ca(self.d)
            old_u, new_u = str(uuid.uuid4()), str(uuid.uuid4())
            old_dir = Path(self.d) / 'certs' / old_u
            old_dir.mkdir(parents=True)
            import base64
            der = b'\x30\x03\x02\x01\x01'
            pem = (b'-----BEGIN CERTIFICATE REQUEST-----\n'
                   + base64.encodebytes(der)
                   + b'-----END CERTIFICATE REQUEST-----\n')
            (old_dir / 'csr.pem').write_bytes(pem)
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, 'parse_cert',
                                   return_value={'subject': 'C=RU, CN=leaf'}):
                info = own_ca.renew_certificate(
                    self.ca_uuid, old_u, new_u, self._spec())
            self.assertFalse(info['has_private_key'])
            cmd = self.calls[0]
            self.assertEqual(cmd[0], 'issuecsr')
            new_dir = Path(self.d) / 'certs' / new_u
            # CSR is carried over and its DER handed to the shim
            self.assertTrue((new_dir / 'csr.pem').exists())
            self.assertEqual((new_dir / 'csr.der').read_bytes(), der)

    def test_renew_without_key_or_csr_fails(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            self._prep_ca(self.d)
            old_u, new_u = str(uuid.uuid4()), str(uuid.uuid4())
            (Path(self.d) / 'certs' / old_u).mkdir(parents=True)
            with self.assertRaisesRegex(own_ca.OwnCAError,
                                        'neither a key container nor a CSR'):
                own_ca.renew_certificate(self.ca_uuid, old_u, new_u, self._spec())


class CapiliteIssueCsrRoutingTest(TestCase):
    """issue_certificate on a capilite CA with an external CSR routes to the
    shim's issuecsr (no genkey, no container marker)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        self.calls = []

    def _fake_run_capi(self, args):
        self.calls.append(args)
        for i, a in enumerate(args):
            if a == '--out':
                Path(args[i + 1]).write_bytes(b'\x30\x03\x02\x01\x01')
        return '{"ok":true}'

    def test_external_csr_uses_issuecsr(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            ca_dir = Path(self.d) / 'cas' / self.ca_uuid
            ca_dir.mkdir(parents=True)
            (ca_dir / 'ca.crt').write_text('stub')
            own_ca._write_backend(ca_dir, 'capilite:ownca_ca_test')
            (ca_dir / 'subject_x500').write_text('C=RU, CN=Root\n')
            (ca_dir / 'key_alg').write_text('gost2012_256\n')
            import base64
            der = b'\x30\x03\x02\x01\x01'
            pem = (b'-----BEGIN CERTIFICATE REQUEST-----\n'
                   + base64.encodebytes(der)
                   + b'-----END CERTIFICATE REQUEST-----\n')
            cert_u = str(uuid.uuid4())
            spec = own_ca.CertSpec(
                common_name='c', subject='/CN=c', key_alg='gost2012_256',
                days=10, ext_lines=['basicConstraints = critical, CA:FALSE'],
                san_dns=[], san_ip=[])
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, 'parse_cert',
                                   return_value={'subject': 'CN=c'}):
                info = own_ca.issue_certificate(
                    self.ca_uuid, cert_u, spec, csr_pem=pem)
            self.assertFalse(info['has_private_key'])
            kinds = [c[0] for c in self.calls]
            self.assertEqual(kinds, ['issuecsr'])     # no genkey
            cert_dir = Path(self.d) / 'certs' / cert_u
            self.assertFalse((cert_dir / 'container').exists())
            self.assertEqual((cert_dir / 'csr.der').read_bytes(), der)


class CapilitePkcs12ExportTest(TestCase):
    """PKCS#12 export routing on the CryptoPro backend: CA export goes through
    the shim with --chain; GOST PBE suites / TK-26 are rejected loudly (the
    shim only produces CryptoPro's native PBE)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        self.calls = []

    def _prep_capilite_ca(self):
        ca_dir = Path(self.d) / 'cas' / self.ca_uuid
        ca_dir.mkdir(parents=True)
        import base64
        der = b'\x30\x03\x02\x01\x01'
        pem = (b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(der)
               + b'-----END CERTIFICATE-----\n')
        (ca_dir / 'ca.crt').write_bytes(pem)
        own_ca._write_backend(ca_dir, 'capilite:ownca_ca_p12test')
        (ca_dir / 'key_alg').write_text('gost2012_256\n')
        return ca_dir, pem

    def _fake_run_capi(self, args):
        self.calls.append(args)
        for i, a in enumerate(args):
            if a == '--out':
                Path(args[i + 1]).write_bytes(b'\x30\x03\x02\x01\x01')
        return '{"ok":true}'

    def test_ca_export_routes_to_shim_with_chain(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            ca_dir, pem = self._prep_capilite_ca()
            parent = Path(self.d) / 'parent.crt'
            parent.write_bytes(pem)
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                blob = own_ca.pkcs12_export_ca(
                    self.ca_uuid, 'pw', chain_paths=[parent])
            self.assertEqual(blob, b'\x30\x03\x02\x01\x01')
            cmd = self.calls[0]
            self.assertEqual(cmd[0], 'exportpfx')
            self.assertIn('ownca_ca_p12test', cmd)
            self.assertIn('--chain', cmd)

    def test_ca_export_rejects_gost_suites(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            self._prep_capilite_ca()
            for suite in ('kuznyechik', 'magma', 'gost89'):
                with self.assertRaisesRegex(own_ca.OwnCAError, 'CryptoPro'):
                    own_ca.pkcs12_export_ca(self.ca_uuid, 'pw', pbe=suite)

    def test_leaf_export_rejects_tk26(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            cert_uuid = str(uuid.uuid4())
            cert_dir = Path(self.d) / 'certs' / cert_uuid
            cert_dir.mkdir(parents=True)
            (cert_dir / 'cert.pem').write_text('stub')
            (cert_dir / 'container').write_text('ownca_crt_p12test\n')
            with self.assertRaisesRegex(own_ca.OwnCAError, 'TK-26'):
                own_ca.pkcs12_export(cert_uuid, [], 'pw', gostkeybag=True)


class CapiliteImportCaTest(TestCase):
    """import_ca_capilite: the PFX goes through the shim (PFXImportCertStore);
    the CA dir gets the capilite backend marker with the container name the
    shim reports. PEM GOST import with CryptoPro active is rejected."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        self.calls = []
        import base64
        self.der = b'\x30\x03\x02\x01\x01'
        self.ca_pem = (b'-----BEGIN CERTIFICATE-----\n'
                       + base64.encodebytes(self.der)
                       + b'-----END CERTIFICATE-----\n')

    def _fake_run_capi(self, args):
        self.calls.append(args)
        for i, a in enumerate(args):
            if a == '--out':
                Path(args[i + 1]).write_bytes(self.der)
        return ('{"out":"x","container":"pfx-11112222-3333","provtype":81,'
                '"subject":"CN=Imported","ok":true}\n')

    def test_import_writes_capilite_marker(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, '_is_ca_cert', return_value=True), \
                 mock.patch.object(own_ca, 'parse_cert', return_value={
                     'subject': 'CN=Imported', 'issuer': 'CN=Imported'}):
                info = own_ca.import_ca_capilite(
                    self.ca_uuid, b'pfxbytes', passphrase='pw')
            self.assertEqual(self.calls[0][0], 'importpfx')
            self.assertTrue(info['is_self_signed'])
            self.assertEqual(info['key_alg'], 'gost2012_512')  # provtype 81
            self.assertEqual(own_ca.read_ca_backend(self.ca_uuid),
                             ('capilite', 'pfx-11112222-3333'))
            ca_dir = Path(self.d) / 'cas' / self.ca_uuid
            self.assertEqual((ca_dir / 'subject_x500').read_text().strip(),
                             'CN=Imported')
            self.assertEqual((ca_dir / 'key_alg').read_text().strip(),
                             'gost2012_512')
            # no PEM key and no pfx left on disk
            self.assertFalse((ca_dir / 'ca.key').exists())
            self.assertFalse((ca_dir / 'import.pfx').exists())

    def test_import_rejects_a_non_gost_container(self):
        """provtype describes the provider the key landed in, not the key. A
        container holding an RSA certificate must be refused here rather than
        recorded as gost2012_256 — a CA whose declared family is a lie would
        then be offered GOST algorithms for an RSA key."""
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, '_is_ca_cert', return_value=True), \
                 mock.patch.object(own_ca, 'detect_cert_key_info',
                                   return_value=('rsa:2048', 'rsa')):
                with self.assertRaisesRegex(own_ca.OwnCAError, 'not a GOST one'):
                    own_ca.import_ca_capilite(self.ca_uuid, b'pfxbytes')

    def test_import_prefers_the_certificate_over_provtype(self):
        # provtype 81 says 512-bit; the certificate says 256 and wins, because
        # the certificate is what every verifier reads.
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, '_is_ca_cert', return_value=True), \
                 mock.patch.object(own_ca, 'detect_cert_key_info',
                                   return_value=('gost2012_256', 'gost')), \
                 mock.patch.object(own_ca, 'parse_cert', return_value={
                     'subject': 'CN=Imported', 'issuer': 'CN=Imported'}):
                info = own_ca.import_ca_capilite(self.ca_uuid, b'pfxbytes')
            self.assertEqual(info['key_alg'], 'gost2012_256')

    def test_import_rejects_non_ca_cert(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, '_is_ca_cert', return_value=False):
                with self.assertRaisesRegex(own_ca.OwnCAError, 'not a CA'):
                    own_ca.import_ca_capilite(self.ca_uuid, b'pfxbytes')

    def test_pem_gost_import_rejected_when_cryptopro_active(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_cryptopro_active_for',
                                   return_value=True), \
                 mock.patch.object(own_ca, '_normalize_cert_pem',
                                   return_value=self.ca_pem), \
                 mock.patch.object(own_ca, '_normalize_key_pem',
                                   return_value=b'key'), \
                 mock.patch.object(own_ca, '_cert_key_match',
                                   return_value=True), \
                 mock.patch.object(own_ca, '_is_ca_cert', return_value=True), \
                 mock.patch.object(own_ca, 'detect_cert_key_alg',
                                   return_value='gost2012_256'):
                with self.assertRaisesRegex(own_ca.OwnCAError, 'PKCS#12/PFX'):
                    own_ca.import_ca(self.ca_uuid, self.ca_pem, b'key')

    def test_failed_import_drops_the_container_it_created(self):
        """importpfx has already put the key in a container by the time the
        post-checks run, and its pfx-<guid> name is not derivable from the CA
        UUID — so a rejection has to drop it here, or the key is unreachable."""
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, '_is_ca_cert', return_value=False):
                with self.assertRaises(own_ca.OwnCAError):
                    own_ca.import_ca_capilite(self.ca_uuid, b'pfxbytes')
            self.assertEqual(
                [a[a.index('--container') + 1] for a in self.calls
                 if a[0] == 'delcontainer'],
                ['pfx-11112222-3333'])

    def test_ca_container_prefers_marker(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            ca_dir = Path(self.d) / 'cas' / self.ca_uuid
            ca_dir.mkdir(parents=True)
            own_ca._write_backend(ca_dir, 'capilite:pfx-imported-name')
            self.assertEqual(own_ca._capi_ca_container(self.ca_uuid),
                             'pfx-imported-name')
            # no marker -> deterministic fallback
            other = str(uuid.uuid4())
            (Path(self.d) / 'cas' / other).mkdir(parents=True)
            self.assertEqual(own_ca._capi_ca_container(other),
                             own_ca._capi_container_for(other))


class CapiContainerCleanupTest(TestCase):
    """Deleting a CA or certificate has to take its CryptoPro key container with
    it: the key lives in the CSP keystore, outside the storage volume, so
    removing the directory alone leaves key material nothing can reach."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.calls = []

    def _fake_run_capi(self, args):
        self.calls.append(args)
        cont = args[args.index('--container') + 1]
        return '{"container":"%s","deleted":true,"ok":true}\n' % cont

    def _deleted(self):
        return [a[a.index('--container') + 1] for a in self.calls
                if a[0] == 'delcontainer']

    def _make_cert(self, container, key_alg='gost2012_256'):
        cert_uuid = str(uuid.uuid4())
        d = Path(self.d) / 'certs' / cert_uuid
        d.mkdir(parents=True)
        (d / 'cert.pem').write_text('stub')
        (d / 'container').write_text(container + '\n')
        (d / 'key_alg').write_text(key_alg + '\n')
        return cert_uuid, d

    def _make_ca(self, backend_marker=None, key_alg=''):
        ca_uuid = str(uuid.uuid4())
        d = Path(self.d) / 'cas' / ca_uuid
        d.mkdir(parents=True)
        (d / 'ca.crt').write_text('stub')
        if backend_marker:
            own_ca._write_backend(d, backend_marker)
        if key_alg:
            (d / 'key_alg').write_text(key_alg + '\n')
        return ca_uuid, d

    def test_cert_delete_drops_its_container(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            cert_uuid, d = self._make_cert('ownca_crt_aaa')
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                own_ca.delete_cert_storage(cert_uuid)
            self.assertFalse(d.exists())
            self.assertEqual(self._deleted(), ['ownca_crt_aaa'])
            # the provider-type hint comes from the cert's own marker
            self.assertIn('gost2012_256', self.calls[0])

    def test_shared_container_survives_until_the_last_reference_goes(self):
        # A renewed certificate deliberately reuses the container of the one it
        # replaces (same key, new validity). Deleting either must not take the
        # key the other still needs.
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            old, _ = self._make_cert('ownca_crt_shared')
            new, _ = self._make_cert('ownca_crt_shared')
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                own_ca.delete_cert_storage(old)
                self.assertEqual(self._deleted(), [])
                own_ca.delete_cert_storage(new)
                self.assertEqual(self._deleted(), ['ownca_crt_shared'])

    def test_ca_delete_uses_the_container_from_its_marker(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            # An imported CA's container is named by PFXImportCertStore, not by
            # our own convention, so only the marker knows it.
            ca_uuid, d = self._make_ca('capilite:pfx-imported-guid', 'gost2012_512')
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                own_ca.delete_ca_storage(ca_uuid)
            self.assertFalse(d.exists())
            self.assertEqual(self._deleted(), ['pfx-imported-guid'])
            self.assertIn('gost2012_512', self.calls[0])

    def test_ca_container_kept_while_a_cert_still_references_it(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            ca_uuid, _ = self._make_ca('capilite:shared-somehow')
            self._make_cert('shared-somehow')
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                own_ca.delete_ca_storage(ca_uuid)
            self.assertEqual(self._deleted(), [])

    def test_openssl_backed_delete_never_calls_the_shim(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            ca_uuid, _ = self._make_ca()
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(cryptopro, 'enabled', return_value=False):
                own_ca.delete_ca_storage(ca_uuid)
            self.assertEqual(self.calls, [])

    def test_rollback_falls_back_to_the_deterministic_name(self):
        # Creation writes its backend marker only after the container exists, so
        # a failure in between leaves a container nothing points at. The
        # deterministic name is derived from the UUID and can only be this CA's.
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            ca_uuid, _ = self._make_ca()
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(cryptopro, 'enabled', return_value=True):
                own_ca.delete_ca_storage(ca_uuid)
            self.assertEqual(self._deleted(), [own_ca._capi_container_for(ca_uuid)])

    def test_container_is_kept_when_the_caller_opts_out(self):
        # What the delete forms pass when the operator leaves the box unticked:
        # the directory goes, the key stays in the provider's keystore.
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            cert_uuid, d = self._make_cert('ownca_crt_keepme')
            ca_uuid, ca_dir = self._make_ca('capilite:ownca_ca_keepme')
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                own_ca.delete_cert_storage(cert_uuid, drop_container=False)
                own_ca.delete_ca_storage(ca_uuid, drop_container=False)
            self.assertFalse(d.exists())
            self.assertFalse(ca_dir.exists())
            self.assertEqual(self.calls, [])

    def test_a_shim_failure_does_not_break_the_delete(self):
        # Cleanup also runs as rollback after a failure; a second failure here
        # must not mask the first, and the directory still has to go.
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            cert_uuid, d = self._make_cert('ownca_crt_bbb')
            with mock.patch.object(own_ca, '_run_capi',
                                   side_effect=own_ca.OwnCAError('shim missing')):
                own_ca.delete_cert_storage(cert_uuid)
            self.assertFalse(d.exists())


class DeleteFormContainerCheckboxTest(TestCase):
    """The delete forms offer "Delete the key container too", unticked by
    default: dropping the container destroys a key nothing can export, so it
    has to be asked for rather than assumed."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.calls = []
        self.admin = User.objects.create_superuser('admin', 'a@e.local', 'pw')
        self.client.force_login(self.admin)
        self.ca = CertificateAuthority.objects.create(
            name='CSP CA', ca_type='root', subject='/CN=CSP CA',
            key_alg='gost2012_256',
        )
        ca_dir = Path(self.d) / 'cas' / str(self.ca.uuid)
        ca_dir.mkdir(parents=True)
        own_ca._write_backend(ca_dir, 'capilite:ownca_ca_csp')
        (ca_dir / 'key_alg').write_text('gost2012_256\n')

    def _fake_run_capi(self, args):
        self.calls.append(args)
        return '{"container":"x","deleted":true,"ok":true}\n'

    def _post_delete(self, data):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                return self.client.post(
                    reverse('ca_delete', args=[self.ca.uuid]), data, follow=True)

    def test_unticked_leaves_the_container_alone(self):
        resp = self._post_delete({})
        self.assertFalse(CertificateAuthority.objects.filter(pk=self.ca.pk).exists())
        self.assertEqual([a[0] for a in self.calls], [])
        self.assertNotContains(resp, 'key container')

    def test_ticked_drops_the_container(self):
        resp = self._post_delete({'drop_container': '1'})
        self.assertFalse(CertificateAuthority.objects.filter(pk=self.ca.pk).exists())
        self.assertEqual([a[0] for a in self.calls], ['delcontainer'])
        self.assertIn('ownca_ca_csp', self.calls[0])
        self.assertContains(resp, 'CryptoPro key container')

    def test_checkbox_only_appears_for_a_cryptopro_backed_ca(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            resp = self.client.get(reverse('ca_detail', args=[self.ca.uuid]))
            self.assertContains(resp, 'name="drop_container"')

            openssl_ca = CertificateAuthority.objects.create(
                name='Plain CA', ca_type='root', subject='/CN=Plain CA',
                key_alg='rsa:2048',
            )
            resp = self.client.get(reverse('ca_detail', args=[openssl_ca.uuid]))
            self.assertNotContains(resp, 'name="drop_container"')

    def test_cert_delete_honours_the_checkbox(self):
        cert = Certificate.objects.create(
            common_name='leaf.example.org', subject='/CN=leaf.example.org',
            issuer_ca=self.ca, key_alg='gost2012_256',
        )
        cert_dir = Path(self.d) / 'certs' / str(cert.uuid)
        cert_dir.mkdir(parents=True)
        (cert_dir / 'container').write_text('ownca_crt_leaf\n')
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                self.client.post(reverse('cert_delete', args=[cert.uuid]),
                                 {'drop_container': '1'}, follow=True)
        self.assertFalse(Certificate.objects.filter(pk=cert.pk).exists())
        self.assertEqual([a[0] for a in self.calls], ['delcontainer'])
        self.assertIn('ownca_crt_leaf', self.calls[0])


class CryptoProPageTest(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('admin', 'a@e.local', 'pw')
        self.client.force_login(self.admin)

    def test_page_redirects_to_maintenance(self):
        with override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker'):
            r = self.client.get('/system/cryptopro/')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r['Location'], '/system/maintenance/')

    def test_set_license_persists(self):
        with override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker'):
            r = self.client.post('/system/cryptopro/', {
                'action': 'set_license', 'license_serial': 'ABCDE-12345',
            })
        self.assertEqual(r.status_code, 302)
        self.assertEqual(CryptoProSettings.get_solo().license_serial, 'ABCDE-12345')


class CrlNumberBackendTest(TestCase):
    """`_init_ca_db` writes an openssl `crlnumber` for EVERY CA, including
    CryptoPro ones — but only `_generate_crl_capilite` advances
    `crlnumber_capi`. Reading by file order would report the initial value
    forever, so the backend has to decide which counter is authoritative."""

    def _ca_dir(self, d, ca_uuid):
        ca_dir = Path(d) / 'cas' / ca_uuid
        ca_dir.mkdir(parents=True)
        return ca_dir

    def test_capilite_ca_reads_capi_counter_not_the_stale_openssl_one(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            ca_uuid = str(uuid.uuid4())
            ca_dir = self._ca_dir(d, ca_uuid)
            own_ca._init_ca_db(ca_dir)          # leaves crlnumber = 1000
            own_ca._write_backend(ca_dir, 'capilite:ownca_ca_abc')
            (ca_dir / 'crlnumber_capi').write_text('7')
            self.assertEqual(own_ca.read_crl_number(ca_uuid), '7')

    def test_openssl_ca_still_reads_the_openssl_counter(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            ca_uuid = str(uuid.uuid4())
            ca_dir = self._ca_dir(d, ca_uuid)
            own_ca._init_ca_db(ca_dir)
            self.assertEqual(own_ca.read_crl_number(ca_uuid), '1000')

    def test_missing_counters_return_empty(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            ca_uuid = str(uuid.uuid4())
            self._ca_dir(d, ca_uuid)
            self.assertEqual(own_ca.read_crl_number(ca_uuid), '')


class CrlReasonCodeTest(TestCase):
    """The revocation reason the operator picks must survive into a CryptoPro
    CRL — the shim has no name->code table, so own_ca resolves it."""

    def test_known_reasons_map_to_rfc5280_codes(self):
        self.assertEqual(own_ca.crl_reason_code('unspecified'), 0)
        self.assertEqual(own_ca.crl_reason_code('keyCompromise'), 1)
        self.assertEqual(own_ca.crl_reason_code('CACompromise'), 2)
        self.assertEqual(own_ca.crl_reason_code('cessationOfOperation'), 5)
        self.assertEqual(own_ca.crl_reason_code('certificateHold'), 6)

    def test_blank_or_unknown_reason_has_no_code(self):
        # None => the caller omits the extension, as openssl does for a
        # revocation recorded without a reason.
        self.assertIsNone(own_ca.crl_reason_code(''))
        self.assertIsNone(own_ca.crl_reason_code(None))
        self.assertIsNone(own_ca.crl_reason_code('notAReason'))

    def test_every_ui_choice_is_mappable(self):
        from dashboard.models import REVOCATION_REASON_CHOICES
        for value, _label in REVOCATION_REASON_CHOICES:
            self.assertIsNotNone(
                own_ca.crl_reason_code(value),
                f'revocation reason {value!r} has no RFC 5280 code',
            )


class GenerateCrlCapiliteTest(TestCase):
    """The `revoked.txt` handed to the shim: serial, revocation time and —
    since the reasonCode fix — the RFC 5280 reason."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        self.ca_dir = Path(self.d) / 'cas' / self.ca_uuid
        self.ca_dir.mkdir(parents=True)
        (self.ca_dir / 'subject_x500').write_text('CN=Capi CA\n')
        (self.ca_dir / 'key_alg').write_text('gost2012_256\n')
        own_ca._write_backend(self.ca_dir, 'capilite:ownca_ca_abc')

    def _fake_run_capi(self, args):
        # the shim writes DER to --out; fake a minimal blob so the PEM wrap works
        Path(args[args.index('--out') + 1]).write_bytes(b'\x30\x03\x02\x01\x01')
        return ''

    def _gen(self, revoked):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                own_ca.generate_crl(self.ca_uuid, revoked=revoked)
        return (self.ca_dir / 'revoked.txt').read_text().splitlines()

    def test_reason_is_appended_as_third_field(self):
        lines = self._gen([('0A1B', 1700000000, 'keyCompromise')])
        self.assertEqual(lines, ['0A1B,1700000000,1'])

    def test_missing_reason_leaves_the_field_off(self):
        # no third field => the shim omits the reasonCode extension entirely
        lines = self._gen([('0A1B', 1700000000, '')])
        self.assertEqual(lines, ['0A1B,1700000000'])

    def test_two_tuple_entries_still_accepted(self):
        lines = self._gen([('0A1B', 1700000000)])
        self.assertEqual(lines, ['0A1B,1700000000'])

    def test_odd_length_serial_is_padded(self):
        lines = self._gen([('a1b', 5, 'superseded')])
        self.assertEqual(lines, ['0a1b,5,4'])

    def test_crl_number_advances_on_the_capi_counter(self):
        self._gen([])
        self.assertEqual((self.ca_dir / 'crlnumber_capi').read_text(), '1')
        self._gen([])
        self.assertEqual((self.ca_dir / 'crlnumber_capi').read_text(), '2')


class CapiliteUiGatingTest(CATestCase):
    """The web UI must not offer operations the CryptoPro backend cannot do.

    The fixture CA is a real openssl RSA CA whose backend marker we flip: the
    gating under test reads `read_ca_backend`, which is algorithm-agnostic, so
    this exercises the exact production path without needing CryptoPro
    installed.
    """

    def setUp(self):
        super().setUp()
        self.cert_uuid = str(uuid.uuid4())
        own_ca.issue_certificate(self.ca_uuid, self.cert_uuid, CertSpec(
            common_name='capi.test',
            subject='/CN=capi.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=self.profile.to_extfile_lines(),
            san_dns=[],
            san_ip=[],
        ))
        self.cert = Certificate.objects.create(
            uuid=self.cert_uuid,
            common_name='capi.test',
            subject='/CN=capi.test',
            issuer_ca=self.ca,
            cert_profile=self.profile,
            key_alg='gost2012_256',   # so the TK-26 checkbox is in play
            has_private_key=True,
        )

    def _go_capilite(self):
        own_ca._write_backend(Path(self._tmp) / 'cas' / self.ca_uuid,
                              'capilite:ownca_ca_test')

    def _detail(self):
        return self.client.get(
            reverse('cert_detail', args=[self.cert.uuid]),
        ).content.decode('utf-8', 'replace')

    # --- openssl baseline: everything stays where it was -------------------

    def test_openssl_cert_still_offers_key_bundle_and_tk26(self):
        body = self._detail()
        self.assertIn(reverse('cert_download', args=[self.cert.uuid, 'key']), body)
        self.assertIn(reverse('cert_download', args=[self.cert.uuid, 'bundle']), body)
        self.assertIn(reverse('cert_download', args=[self.cert.uuid, 'csr']), body)
        self.assertIn('gostkeybag', body)

    # --- capilite: the incompatible actions disappear ----------------------

    def test_capilite_hides_key_and_bundle_downloads(self):
        self._go_capilite()
        body = self._detail()
        self.assertNotIn(reverse('cert_download', args=[self.cert.uuid, 'key']), body)
        self.assertNotIn(reverse('cert_download', args=[self.cert.uuid, 'bundle']), body)
        # the cert itself is still downloadable — only key-bearing exports go
        self.assertIn(reverse('cert_download', args=[self.cert.uuid, 'cert']), body)

    def test_capilite_hides_tk26_checkbox(self):
        self._go_capilite()
        self.assertNotIn('gostkeybag', self._detail())

    def test_capilite_hides_csr_download_when_there_is_no_csr(self):
        self._go_capilite()
        # server-side keygen on the CryptoPro backend produces no PKCS#10
        (Path(self._tmp) / 'certs' / self.cert_uuid / 'csr.pem').unlink()
        body = self._detail()
        self.assertNotIn(reverse('cert_download', args=[self.cert.uuid, 'csr']), body)

    def test_capilite_keeps_csr_download_for_an_external_csr(self):
        self._go_capilite()
        body = self._detail()
        self.assertIn(reverse('cert_download', args=[self.cert.uuid, 'csr']), body)

    # --- server side refuses too (direct links / stale pages) --------------

    def test_key_download_refused_on_capilite(self):
        self._go_capilite()
        resp = self.client.get(
            reverse('cert_download', args=[self.cert.uuid, 'key']), follow=True)
        self.assertContains(resp, 'CryptoPro CSP')
        self.assertNotEqual(resp['Content-Type'], 'application/x-pem-file')

    def test_bundle_download_refused_on_capilite(self):
        """Regression: this used to succeed and silently ship a bundle with no
        private key in it."""
        self._go_capilite()
        resp = self.client.get(
            reverse('cert_download', args=[self.cert.uuid, 'bundle']), follow=True)
        self.assertContains(resp, 'CryptoPro CSP')
        self.assertNotEqual(resp['Content-Type'], 'application/x-pem-file')

    def test_csr_download_refused_on_capilite_when_absent(self):
        self._go_capilite()
        (Path(self._tmp) / 'certs' / self.cert_uuid / 'csr.pem').unlink()
        resp = self.client.get(
            reverse('cert_download', args=[self.cert.uuid, 'csr']), follow=True)
        self.assertContains(resp, 'no PKCS#10 request exists')

    def test_bundle_download_still_works_on_openssl(self):
        resp = self.client.get(
            reverse('cert_download', args=[self.cert.uuid, 'bundle']))
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'BEGIN CERTIFICATE', resp.content)

    # --- CA-level p12 suite ------------------------------------------------

    def test_ca_p12_suite_locked_to_standard_on_capilite(self):
        self._go_capilite()
        body = self.client.get(
            reverse('ca_detail', args=[self.ca.uuid]),
        ).content.decode('utf-8', 'replace')
        self.assertNotIn('value="kuznyechik"', body)
        self.assertNotIn('value="gost89"', body)
        self.assertIn('name="pbe" value="standard"', body)

    def test_ca_p12_suite_choices_intact_on_openssl(self):
        body = self.client.get(
            reverse('ca_detail', args=[self.ca.uuid]),
        ).content.decode('utf-8', 'replace')
        self.assertIn('value="kuznyechik"', body)
        self.assertIn('value="gost89"', body)


class RevokeThenCrlOrderingTest(CATestCase):
    """A CryptoPro CA's CRL is built from the DB, so the revocation has to be
    committed BEFORE the CRL is regenerated — otherwise the cert just revoked
    is missing from the CRL it triggered."""

    def setUp(self):
        super().setUp()
        self.cert_uuid = str(uuid.uuid4())
        info = own_ca.issue_certificate(self.ca_uuid, self.cert_uuid, CertSpec(
            common_name='revoke-order.test',
            subject='/CN=revoke-order.test',
            key_alg='rsa:2048',
            days=10,
            ext_lines=self.profile.to_extfile_lines(),
            san_dns=[],
            san_ip=[],
        ))
        self.cert = Certificate.objects.create(
            uuid=self.cert_uuid,
            common_name='revoke-order.test',
            subject='/CN=revoke-order.test',
            issuer_ca=self.ca,
            key_alg='rsa:2048',
            serial_hex=info.get('serial_hex', ''),
        )

    def test_revoked_cert_is_in_the_crl_it_triggered(self):
        seen = {}

        def _capture(ca_uuid, revoked=None):
            seen['revoked'] = list(revoked or [])

        with mock.patch.object(own_ca, 'generate_crl', _capture):
            self.client.post(reverse('cert_revoke', args=[self.cert.uuid]),
                             {'reason': 'keyCompromise'})

        serials = [e[0] for e in seen['revoked']]
        self.assertIn(self.cert.serial_hex, serials)
        entry = next(e for e in seen['revoked'] if e[0] == self.cert.serial_hex)
        self.assertEqual(entry[2], 'keyCompromise')


class GeneralNameSplitTest(TestCase):
    """issuerAltName arrives as openssl GeneralName strings; the shim wants them
    bucketed by type, and anything it cannot encode must be visible to the
    caller rather than dropped."""

    def test_splits_known_prefixes_case_insensitively(self):
        buckets, unsupported = own_ca._split_general_names([
            'DNS:ca.example', 'email:ca@example', 'URI:http://ca/x',
            'IP:10.0.0.1', 'uri:http://ca/y',
        ])
        self.assertEqual(buckets['dns'], ['ca.example'])
        self.assertEqual(buckets['email'], ['ca@example'])
        self.assertEqual(buckets['uri'], ['http://ca/x', 'http://ca/y'])
        self.assertEqual(buckets['ip'], ['10.0.0.1'])
        self.assertEqual(unsupported, [])

    def test_uri_value_keeps_its_own_colons(self):
        buckets, _ = own_ca._split_general_names(['URI:http://ca:8080/crl'])
        self.assertEqual(buckets['uri'], ['http://ca:8080/crl'])

    def test_unknown_type_and_bare_value_are_reported(self):
        _buckets, unsupported = own_ca._split_general_names([
            'dirName:sec', 'otherName:1.2.3;UTF8:x', 'no-prefix', 'DNS:',
        ])
        self.assertIn('dirName:sec', unsupported)
        self.assertIn('no-prefix', unsupported)
        self.assertIn('DNS:', unsupported)

    def test_blank_entries_are_skipped_not_reported(self):
        buckets, unsupported = own_ca._split_general_names(['', '   ', None])
        self.assertEqual(unsupported, [])
        self.assertEqual(buckets['dns'], [])

    def test_or_raise_wraps_unsupported(self):
        with self.assertRaisesRegex(own_ca.OwnCAError, 'dirName:sec'):
            own_ca._general_names_or_raise(['dirName:sec'], 'issuerAltName')


class ExtspecDistributionPointerTest(TestCase):
    """SIA / freshestCRL / issuerAltName in the extspec — the CA-cert pointers
    that used to be dropped silently on the CryptoPro backend (R1)."""

    def _write(self, **kw):
        d = Path(tempfile.mkdtemp())
        p = d / 'ext.txt'
        base = dict(is_ca=True, pathlen=-1, ku=[], ku_critical=False,
                    eku=[], eku_critical=False)
        base.update(kw)
        own_ca._write_extspec(p, **base)
        return p.read_text()

    def test_sia_and_freshest_crl_emitted(self):
        text = self._write(sia_repo='http://x/repo',
                           freshest_crl='http://x/delta.crl')
        self.assertIn('sia_repo=http://x/repo', text)
        self.assertIn('freshest_crl=http://x/delta.crl', text)

    def test_issuer_alt_names_emitted_by_type(self):
        buckets, _ = own_ca._split_general_names(
            ['DNS:ca.example', 'email:ca@example', 'URI:http://ca/x', 'IP:10.0.0.1'])
        text = self._write(issuer_alt_names=buckets)
        self.assertIn('ian_dns=ca.example', text)
        self.assertIn('ian_email=ca@example', text)
        self.assertIn('ian_uri=http://ca/x', text)
        self.assertIn('ian_ip=0a000001', text)   # hex, like san_ip

    def test_absent_pointers_emit_nothing(self):
        text = self._write()
        for key in ('sia_repo=', 'freshest_crl=', 'ian_'):
            self.assertNotIn(key, text)


class CapiParamsetArgsTest(TestCase):
    """`genkey --paramset` args (R2): the operator's GOST paramset choice has to
    reach the container, and an invalid one must fail before a key exists."""

    def test_gost_256_accepts_its_five_sets(self):
        for ps in own_ca.GOST_PARAMSET_CHOICES_256:
            self.assertEqual(own_ca._capi_paramset_args('gost2012_256', ps),
                             ['--paramset', ps])

    def test_gost_512_accepts_its_three_sets(self):
        for ps in own_ca.GOST_PARAMSET_CHOICES_512:
            self.assertEqual(own_ca._capi_paramset_args('gost2012_512', ps),
                             ['--paramset', ps])

    def test_exchange_sets_are_rejected_for_512(self):
        # XA/XB exist only for 256-bit keys
        with self.assertRaisesRegex(own_ca.OwnCAError, 'invalid paramset'):
            own_ca._capi_paramset_args('gost2012_512', 'XA')

    def test_unknown_paramset_raises(self):
        with self.assertRaisesRegex(own_ca.OwnCAError, 'invalid paramset'):
            own_ca._capi_paramset_args('gost2012_256', 'Z')

    def test_blank_falls_back_to_the_module_default(self):
        self.assertEqual(own_ca._capi_paramset_args('gost2012_256', ''),
                         ['--paramset', own_ca.DEFAULT_GOST_PARAMSET])

    def test_non_gost_alg_gets_no_paramset_arg(self):
        self.assertEqual(own_ca._capi_paramset_args('rsa:2048', 'A'), [])


class CapiliteIssueParamsetTest(TestCase):
    """The paramset must actually be handed to the shim on server-side keygen —
    it used to be dropped between CertSpec and `genkey`."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        ca_dir = Path(self.d) / 'cas' / self.ca_uuid
        ca_dir.mkdir(parents=True)
        (ca_dir / 'subject_x500').write_text('CN=Capi CA\n')
        (ca_dir / 'key_alg').write_text('gost2012_256\n')
        (ca_dir / 'ca.crt').write_bytes(b'-----BEGIN CERTIFICATE-----\nAA==\n'
                                        b'-----END CERTIFICATE-----\n')
        own_ca._write_backend(ca_dir, 'capilite:ownca_ca_abc')
        self.calls = []

    def _fake_run_capi(self, args):
        self.calls.append(args)
        if '--out' in args:
            Path(args[args.index('--out') + 1]).write_bytes(b'\x30\x03\x02\x01\x01')
        return ''

    def _spec(self, paramset):
        return own_ca.CertSpec(
            common_name='x', subject='/CN=x', key_alg='gost2012_256', days=1,
            ext_lines=['basicConstraints = critical, CA:FALSE'],
            san_dns=[], san_ip=[], paramset=paramset,
        )

    def _issue(self, paramset):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, 'parse_cert', return_value={}):
                own_ca.issue_certificate(self.ca_uuid, str(uuid.uuid4()),
                                         self._spec(paramset))
        return next(c for c in self.calls if c[0] == 'genkey')

    def test_requested_paramset_reaches_genkey(self):
        genkey = self._issue('XB')
        self.assertIn('--paramset', genkey)
        self.assertEqual(genkey[genkey.index('--paramset') + 1], 'XB')

    def test_invalid_paramset_fails_before_any_shim_call(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi):
                with self.assertRaisesRegex(own_ca.OwnCAError, 'invalid paramset'):
                    own_ca.issue_certificate(self.ca_uuid, str(uuid.uuid4()),
                                             self._spec('Z'))
        self.assertEqual([c for c in self.calls if c[0] == 'genkey'], [])


class CrlDaysTest(TestCase):
    """CRL validity (R5). Both backends must use the same configured span —
    the CryptoPro path used to hardcode 7 days while openssl used 30."""

    def _ca(self, d, marker=None):
        ca_uuid = str(uuid.uuid4())
        ca_dir = Path(d) / 'cas' / ca_uuid
        ca_dir.mkdir(parents=True)
        if marker is not None:
            (ca_dir / 'crl_days').write_text(marker)
        return ca_uuid, ca_dir

    def test_marker_is_read(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            ca_uuid, _ = self._ca(d, '14\n')
            self.assertEqual(own_ca._ca_crl_days(ca_uuid), 14)

    def test_missing_or_bad_marker_falls_back_to_the_default(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            for marker in (None, 'nonsense\n', '0\n', '-5\n'):
                ca_uuid, _ = self._ca(d, marker)
                self.assertEqual(own_ca._ca_crl_days(ca_uuid),
                                 own_ca.DEFAULT_CRL_DAYS)

    def test_written_value_matches_the_openssl_cnf_default(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            _ca_uuid, ca_dir = self._ca(d)
            own_ca._write_ca_crl_days(ca_dir, None)
            self.assertEqual((ca_dir / 'crl_days').read_text().strip(),
                             str(own_ca._DEFAULT_CNF_VARS['default_crl_days']))

    def test_profile_vars_override_is_recorded(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            _ca_uuid, ca_dir = self._ca(d)
            own_ca._write_ca_crl_days(ca_dir, {'default_crl_days': 7})
            self.assertEqual((ca_dir / 'crl_days').read_text().strip(), '7')

    def test_capilite_gencrl_uses_the_configured_span(self):
        d = tempfile.mkdtemp()
        calls = []

        def fake(args):
            calls.append(args)
            Path(args[args.index('--out') + 1]).write_bytes(b'\x30\x03\x02\x01\x01')
            return ''

        with override_settings(OWNCA_STORAGE_DIR=d):
            ca_uuid, ca_dir = self._ca(d, '21\n')
            (ca_dir / 'subject_x500').write_text('CN=CA\n')
            (ca_dir / 'key_alg').write_text('gost2012_256\n')
            own_ca._write_backend(ca_dir, 'capilite:c')
            with mock.patch.object(own_ca, '_run_capi', fake):
                own_ca.generate_crl(ca_uuid, revoked=[])
                args = calls[-1]
                self.assertEqual(args[args.index('--days') + 1], '21')
                # an explicit argument still wins over the marker
                own_ca.generate_crl(ca_uuid, revoked=[], days=3)
                args = calls[-1]
                self.assertEqual(args[args.index('--days') + 1], '3')


class OpensslCrlDaysTest(CATestCase):
    """The openssl backend keeps reading default_crl_days from its own cnf, and
    an explicit override reaches it as -crldays."""

    def test_default_span_comes_from_the_cnf(self):
        own_ca.generate_crl(self.ca_uuid)
        text = own_ca._run(['crl', '-in', str(self.ca.crl_path), '-noout', '-text'])
        self.assertIn('Next Update', text)

    def test_explicit_days_are_passed_through(self):
        seen = {}
        real = own_ca._run

        def spy(args, **kw):
            if args and args[0] == 'ca':
                seen['args'] = args
            return real(args, **kw)

        with mock.patch.object(own_ca, '_run', spy):
            own_ca.generate_crl(self.ca_uuid, days=5)
        self.assertIn('-crldays', seen['args'])
        self.assertEqual(seen['args'][seen['args'].index('-crldays') + 1], '5')


class CapiliteServerKeygenCsrTest(TestCase):
    """R3: a server-generated key on the CryptoPro backend must still leave a
    csr.pem, the way the openssl backend does."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        ca_dir = Path(self.d) / 'cas' / self.ca_uuid
        ca_dir.mkdir(parents=True)
        (ca_dir / 'subject_x500').write_text('CN=Capi CA\n')
        (ca_dir / 'key_alg').write_text('gost2012_256\n')
        (ca_dir / 'ca.crt').write_bytes(b'-----BEGIN CERTIFICATE-----\nAA==\n'
                                        b'-----END CERTIFICATE-----\n')
        own_ca._write_backend(ca_dir, 'capilite:ownca_ca_abc')
        self.calls = []
        self.fail_gencsr = False

    def _fake_run_capi(self, args):
        self.calls.append(args)
        if args[0] == 'gencsr' and self.fail_gencsr:
            raise own_ca.OwnCAError('gencsr: not supported by this shim')
        if '--out' in args:
            Path(args[args.index('--out') + 1]).write_bytes(b'\x30\x03\x02\x01\x01')
        return ''

    def _spec(self, **kw):
        base = dict(common_name='leaf', subject='/CN=leaf/O=OwnCA',
                    key_alg='gost2012_256', days=30,
                    ext_lines=['basicConstraints = critical, CA:FALSE'],
                    san_dns=[], san_ip=[])
        base.update(kw)
        return own_ca.CertSpec(**base)

    def _issue(self, cert_uuid):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, 'parse_cert', return_value={}):
                return own_ca.issue_certificate(self.ca_uuid, cert_uuid, self._spec())

    def test_gencsr_is_called_with_the_subject_container_and_dn(self):
        cert_uuid = str(uuid.uuid4())
        self._issue(cert_uuid)
        gencsr = next(c for c in self.calls if c[0] == 'gencsr')
        self.assertEqual(gencsr[gencsr.index('--container') + 1],
                         own_ca._capi_cert_container_for(cert_uuid))
        self.assertEqual(gencsr[gencsr.index('--subject') + 1], 'CN=leaf, O=OwnCA')

    def test_csr_pem_lands_on_disk_and_the_der_scratch_is_removed(self):
        cert_uuid = str(uuid.uuid4())
        self._issue(cert_uuid)
        cert_dir = Path(self.d) / 'certs' / cert_uuid
        self.assertTrue((cert_dir / 'csr.pem').exists())
        self.assertIn(b'BEGIN CERTIFICATE REQUEST',
                      (cert_dir / 'csr.pem').read_bytes())
        self.assertFalse((cert_dir / 'csr.der').exists())

    def test_a_shim_without_gencsr_does_not_break_issuance(self):
        """The certificate is signed from the container, not from the request —
        a missing csr.pem must not turn a good issuance into a failure."""
        self.fail_gencsr = True
        cert_uuid = str(uuid.uuid4())
        info = self._issue(cert_uuid)
        self.assertTrue(info['has_private_key'])
        self.assertTrue((Path(self.d) / 'certs' / cert_uuid / 'cert.pem').exists())
        self.assertFalse((Path(self.d) / 'certs' / cert_uuid / 'csr.pem').exists())

    def test_renewal_carries_the_csr_forward(self):
        old_uuid = str(uuid.uuid4())
        self._issue(old_uuid)
        new_uuid = str(uuid.uuid4())
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, '_run_capi', self._fake_run_capi), \
                 mock.patch.object(own_ca, 'parse_cert', return_value={}):
                own_ca.renew_certificate(self.ca_uuid, old_uuid, new_uuid, self._spec())
        new_dir = Path(self.d) / 'certs' / new_uuid
        self.assertTrue((new_dir / 'csr.pem').exists())
        # still re-issued from the container, not via issuecsr
        self.assertTrue(any(c[0] == 'issue' for c in self.calls))
        self.assertFalse(any(c[0] == 'issuecsr' for c in self.calls))


class KeyIdentifierProfileFlagsTest(TestCase):
    """R7: the subjectKeyIdentifier / authorityKeyIdentifier toggles.

    OpenSSL 3.x adds both extensions to every certificate `openssl ca` signs
    unless they are explicitly disabled, so "line absent" means ON and only
    `= none` means OFF. The CryptoPro backend has to follow the same rule or
    the two backends drift apart."""

    BC = 'basicConstraints = critical, CA:FALSE'

    def test_absent_lines_mean_enabled(self):
        prof = own_ca._parse_profile_ext_lines([self.BC])
        self.assertTrue(prof['want_ski'])
        self.assertTrue(prof['want_aki'])
        self.assertFalse(prof['aki_issuer'])

    def test_none_disables(self):
        prof = own_ca._parse_profile_ext_lines([
            self.BC, 'subjectKeyIdentifier = none',
            'authorityKeyIdentifier = none',
        ])
        self.assertFalse(prof['want_ski'])
        self.assertFalse(prof['want_aki'])

    def test_hash_and_keyid_enable(self):
        prof = own_ca._parse_profile_ext_lines([
            self.BC, 'subjectKeyIdentifier = hash',
            'authorityKeyIdentifier = keyid:always',
        ])
        self.assertTrue(prof['want_ski'])
        self.assertTrue(prof['want_aki'])
        self.assertFalse(prof['aki_issuer'])

    def test_issuer_always_is_detected(self):
        prof = own_ca._parse_profile_ext_lines([
            self.BC, 'authorityKeyIdentifier = keyid:always, issuer:always',
        ])
        self.assertTrue(prof['want_aki'])
        self.assertTrue(prof['aki_issuer'])


class KeyIdentifierRenderingTest(TestCase):
    """Both line sources must spell the toggles the same way, and both must
    default to ON."""

    def _ki_lines(self, lines):
        return [l for l in lines if 'KeyIdentifier' in l]

    def test_default_profile_enables_both(self):
        from dashboard.models import CertProfile
        self.assertEqual(
            self._ki_lines(CertProfile(name='d', display_name='d').to_extfile_lines()),
            ['subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid:always'])

    def test_profile_off_renders_none_not_omission(self):
        from dashboard.models import CertProfile
        p = CertProfile(name='d', display_name='d',
                        include_subject_key_identifier=False,
                        include_authority_key_identifier=False)
        self.assertEqual(self._ki_lines(p.to_extfile_lines()),
                         ['subjectKeyIdentifier = none',
                          'authorityKeyIdentifier = none'])

    def test_profile_issuer_always(self):
        from dashboard.models import CertProfile
        p = CertProfile(name='d', display_name='d', aki_include_issuer=True)
        self.assertIn('authorityKeyIdentifier = keyid:always, issuer:always',
                      p.to_extfile_lines())

    def test_free_form_matches_the_profile_rendering(self):
        from dashboard.views import _build_free_form_payload
        on, _ = _build_free_form_payload({
            'include_subject_key_identifier': 'on',
            'include_authority_key_identifier': 'on',
        })
        self.assertEqual(self._ki_lines(on),
                         ['subjectKeyIdentifier = hash',
                          'authorityKeyIdentifier = keyid:always'])
        off, _ = _build_free_form_payload({})
        self.assertEqual(self._ki_lines(off),
                         ['subjectKeyIdentifier = none',
                          'authorityKeyIdentifier = none'])

    def test_none_survives_the_capilite_extension_filter(self):
        # 'subjectkeyidentifier'/'authoritykeyidentifier' are supported keys, so
        # a disabled toggle must not be mistaken for an unsupported extension
        spec = own_ca.CertSpec(
            common_name='x', subject='/CN=x', key_alg='gost2012_256', days=1,
            ext_lines=['subjectKeyIdentifier = none',
                       'authorityKeyIdentifier = none'],
            san_dns=[], san_ip=[])
        own_ca._reject_unsupported_spec_capilite(spec)   # no raise


class CapiKeyIdArgsTest(TestCase):
    """`_capi_key_id_args` — what reaches the extspec for a given profile."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ca_uuid = str(uuid.uuid4())
        self.ca_dir = Path(self.d) / 'cas' / self.ca_uuid
        self.ca_dir.mkdir(parents=True)
        (self.ca_dir / 'subject_x500').write_text('CN=Sub CA, O=Own\n')
        own_ca._store_x500_issuer(self.ca_dir, 'CN=Root CA, O=Own')

    def _args(self, ext_lines):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, 'parse_cert',
                                   return_value={'serial_hex': '4ABC'}):
                return own_ca._capi_key_id_args(
                    self.ca_uuid, own_ca._parse_profile_ext_lines(ext_lines))

    def test_keyid_only_aki_carries_no_issuer_fields(self):
        args = self._args(['authorityKeyIdentifier = keyid:always'])
        self.assertEqual(args, {'want_ski': True, 'want_aki': True})

    def test_issuer_always_pulls_the_ca_certs_issuer_and_serial(self):
        args = self._args(['authorityKeyIdentifier = keyid:always, issuer:always'])
        self.assertEqual(args['aki_issuer_dn'], 'CN=Root CA, O=Own')
        self.assertEqual(args['aki_issuer_serial'], '4ABC')

    def test_disabled_toggles_are_passed_through(self):
        args = self._args(['subjectKeyIdentifier = none',
                           'authorityKeyIdentifier = none'])
        self.assertEqual(args, {'want_ski': False, 'want_aki': False})

    def test_odd_length_serial_is_padded(self):
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, 'parse_cert',
                                   return_value={'serial_hex': 'ABC'}):
                self.assertEqual(own_ca._ca_cert_serial_hex(self.ca_uuid), '0ABC')

    def test_issuer_falls_back_to_the_certificate_when_unmarked(self):
        other = str(uuid.uuid4())
        (Path(self.d) / 'cas' / other).mkdir(parents=True)
        with override_settings(OWNCA_STORAGE_DIR=self.d):
            with mock.patch.object(own_ca, 'parse_cert',
                                   return_value={'issuer': '/CN=Parent/O=Own'}):
                self.assertEqual(own_ca._read_x500_issuer(other),
                                 'CN=Parent, O=Own')


class ExtspecKeyIdentifierTest(TestCase):
    """The extspec lines the shim consumes for SKI/AKI."""

    def _write(self, **kw):
        p = Path(tempfile.mkdtemp()) / 'ext.txt'
        base = dict(is_ca=False, pathlen=-1, ku=[], ku_critical=False,
                    eku=[], eku_critical=False)
        base.update(kw)
        own_ca._write_extspec(p, **base)
        return p.read_text()

    def test_disabled_identifiers_emit_no_keys(self):
        text = self._write(want_ski=False, want_aki=False)
        self.assertNotIn('ski=', text)
        self.assertNotIn('aki=', text)

    def test_issuer_fields_ride_along_with_aki(self):
        text = self._write(want_aki=True, aki_issuer_dn='CN=Root CA, O=Own',
                           aki_issuer_serial='4ABC')
        self.assertIn('aki=1', text)
        self.assertIn('aki_issuer_dn=CN=Root CA, O=Own', text)
        self.assertIn('aki_issuer_serial=4ABC', text)

    def test_no_issuer_fields_without_aki(self):
        text = self._write(want_aki=False, aki_issuer_dn='CN=Root CA',
                           aki_issuer_serial='4ABC')
        self.assertNotIn('aki_issuer_dn', text)
        self.assertNotIn('aki_issuer_serial', text)


class ProviderParamsetCapabilityTest(TestCase):
    """U6: the paramsets offered for a CryptoPro CA come from the provider
    (PP_ENUM_SIGNATUREOID), not from the gost-engine table."""

    OIDS_256 = ['1.2.643.2.2.35.1', '1.2.643.2.2.35.2', '1.2.643.2.2.35.3',
                '1.2.643.2.2.36.0', '1.2.643.2.2.36.1']

    def setUp(self):
        own_ca._capi_paramset_cache.clear()
        self.calls = []

    def tearDown(self):
        own_ca._capi_paramset_cache.clear()

    def _shim(self, oids):
        def fake(args):
            self.calls.append(args)
            import json
            return json.dumps({'alg': args[-1], 'oids': oids, 'ok': True}) + '\n'
        return fake

    def test_oid_table_covers_every_offered_choice(self):
        """The name->OID table and the choice lists must not drift apart, or the
        capability check would compare against the wrong identifiers."""
        for alg in ('gost2012_256', 'gost2012_512'):
            self.assertEqual(sorted(own_ca.GOST_PARAMSET_OIDS[alg]),
                             sorted(own_ca.gost_paramset_choices(alg)))

    def test_provider_list_narrows_the_offer(self):
        with mock.patch.object(own_ca, '_run_capi', self._shim(self.OIDS_256[:3])):
            self.assertEqual(own_ca.capi_supported_paramsets('gost2012_256'),
                             ['A', 'B', 'C'])   # XA/XB dropped

    def test_full_provider_list_keeps_everything(self):
        with mock.patch.object(own_ca, '_run_capi', self._shim(self.OIDS_256)):
            self.assertEqual(own_ca.capi_supported_paramsets('gost2012_256'),
                             ['A', 'B', 'C', 'XA', 'XB'])

    def test_unknown_provider_oids_are_ignored(self):
        # CryptoPro also advertises TC26-256 sets the dashboard does not offer
        extra = self.OIDS_256[:1] + ['1.2.643.7.1.2.1.1.4']
        with mock.patch.object(own_ca, '_run_capi', self._shim(extra)):
            self.assertEqual(own_ca.capi_supported_paramsets('gost2012_256'), ['A'])

    def test_probe_failure_falls_back_to_the_static_list(self):
        def boom(args):
            raise own_ca.OwnCAError('shim missing')
        with mock.patch.object(own_ca, '_run_capi', boom):
            self.assertEqual(own_ca.capi_supported_paramsets('gost2012_256'),
                             own_ca.GOST_PARAMSET_CHOICES_256)

    def test_empty_intersection_falls_back_rather_than_offering_nothing(self):
        with mock.patch.object(own_ca, '_run_capi', self._shim(['9.9.9'])):
            self.assertEqual(own_ca.capi_supported_paramsets('gost2012_256'),
                             own_ca.GOST_PARAMSET_CHOICES_256)

    def test_result_is_cached_so_the_form_costs_one_probe(self):
        with mock.patch.object(own_ca, '_run_capi', self._shim(self.OIDS_256)):
            own_ca.capi_supported_paramsets('gost2012_256')
            own_ca.capi_supported_paramsets('gost2012_256')
        self.assertEqual(len(self.calls), 1)

    def test_failed_probe_is_not_cached(self):
        def boom(args):
            raise own_ca.OwnCAError('shim missing')
        with mock.patch.object(own_ca, '_run_capi', boom):
            own_ca.capi_supported_paramsets('gost2012_256')
        with mock.patch.object(own_ca, '_run_capi', self._shim(self.OIDS_256[:1])):
            self.assertEqual(own_ca.capi_supported_paramsets('gost2012_256'), ['A'])

    def test_non_gost_algorithms_have_no_paramsets(self):
        self.assertEqual(own_ca.capi_supported_paramsets('rsa:2048'), [])
        self.assertEqual(own_ca.paramset_choices_for_ca('rsa:2048'), [])

    def test_choices_route_by_ca_backend(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_STORAGE_DIR=d):
            capi_ca, ossl_ca = str(uuid.uuid4()), str(uuid.uuid4())
            for u in (capi_ca, ossl_ca):
                (Path(d) / 'cas' / u).mkdir(parents=True)
            own_ca._write_backend(Path(d) / 'cas' / capi_ca, 'capilite:c')
            with mock.patch.object(own_ca, '_run_capi', self._shim(self.OIDS_256[:2])):
                self.assertEqual(
                    own_ca.paramset_choices_for_ca('gost2012_256', capi_ca), ['A', 'B'])
            # an openssl CA keeps the gost-engine list and never probes the shim
            self.calls.clear()
            with mock.patch.object(own_ca, '_run_capi', self._shim(self.OIDS_256)):
                self.assertEqual(
                    own_ca.paramset_choices_for_ca('gost2012_256', ossl_ca),
                    own_ca.GOST_PARAMSET_CHOICES_256)
            self.assertEqual(self.calls, [])

    def test_genkey_rejects_a_set_the_provider_lacks(self):
        with mock.patch.object(own_ca, '_run_capi', self._shim(self.OIDS_256[:3])):
            with self.assertRaisesRegex(own_ca.OwnCAError, 'supports A, B, C'):
                own_ca._capi_paramset_args('gost2012_256', 'XB')


class IssueFormParamsetContextTest(CATestCase):
    """The issue form only pays for a provider probe when some CA is actually
    CryptoPro-backed, and the template gets both lists to choose from."""

    def setUp(self):
        super().setUp()
        own_ca._capi_paramset_cache.clear()

    def tearDown(self):
        own_ca._capi_paramset_cache.clear()
        super().tearDown()

    def test_no_capilite_ca_means_no_probe_and_empty_capi_lists(self):
        calls = []
        with mock.patch.object(own_ca, '_run_capi', lambda a: calls.append(a) or ''):
            resp = self.client.get(reverse('custom_cert_issue'))
        self.assertEqual(calls, [])
        self.assertEqual(list(resp.context['capi_paramsets_256']), [])
        self.assertEqual(list(resp.context['capi_paramsets_512']), [])
        self.assertEqual(list(resp.context['gost_paramsets_256']),
                         own_ca.GOST_PARAMSET_CHOICES_256)

    def test_capilite_ca_supplies_the_provider_lists(self):
        own_ca._write_backend(Path(self._tmp) / 'cas' / self.ca_uuid, 'capilite:c')

        def fake(args):
            import json
            oids = (['1.2.643.2.2.35.1', '1.2.643.2.2.35.2']
                    if args[-1] == 'gost2012_256' else ['1.2.643.7.1.2.1.2.1'])
            return json.dumps({'oids': oids, 'ok': True}) + '\n'

        with mock.patch.object(own_ca, '_run_capi', fake):
            resp = self.client.get(reverse('custom_cert_issue'))
        self.assertEqual(list(resp.context['capi_paramsets_256']), ['A', 'B'])
        self.assertEqual(list(resp.context['capi_paramsets_512']), ['A'])
        body = resp.content.decode('utf-8', 'replace')
        self.assertIn('data-capi-paramsets-256="A,B"', body)
        self.assertIn('data-backend="capilite"', body)


class ProfileIncompatibilityTest(TestCase):
    """U7: what a CryptoPro-backed CA would refuse in a profile, computed from
    the same rule that raises the refusal at issuance."""

    def _profile(self, **kw):
        from dashboard.tests.conftest import make_cert_profile
        return make_cert_profile(**kw)

    def test_plain_profile_is_compatible(self):
        self.assertEqual(self._profile().capilite_incompatibilities(), [])

    def test_name_constraints_are_reported(self):
        p = self._profile(name_constraints_permitted='DNS:.example.org')
        self.assertIn('nameconstraints', p.capilite_incompatibilities())

    def test_policy_constraints_and_inhibit_any_policy(self):
        p = self._profile(policy_constraints_require_explicit=0,
                          inhibit_any_policy=0)
        problems = p.capilite_incompatibilities()
        self.assertIn('policyconstraints', problems)
        self.assertIn('inhibitanypolicy', problems)

    def test_extra_extensions_are_reported(self):
        p = self._profile(extra_extensions='1.2.3.4 = ASN1:UTF8String:x')
        self.assertIn('1.2.3.4', p.capilite_incompatibilities())

    def test_extension_placement_oid_fields_are_reported(self):
        """These render into ext lines only once values are supplied at issue
        time, so the profile looks clean until it is far too late."""
        from dashboard.models import CustomOidDefinition, ProfileOidField
        p = self._profile()
        od = CustomOidDefinition.objects.create(
            oid='1.2.643.100.1', label='OGRN',
            asn1_type='NUMERIC', placement='extension')
        ProfileOidField.objects.create(profile=p, oid_definition=od)
        self.assertIn('custom OID extension 1.2.643.100.1',
                      p.capilite_incompatibilities())

    def test_othername_san_fields_are_reported(self):
        from dashboard.models import CustomOidDefinition, ProfileOidField
        p = self._profile()
        od = CustomOidDefinition.objects.create(
            oid='1.2.643.100.9', label='Other',
            asn1_type='UTF8', placement='san_othername')
        ProfileOidField.objects.create(profile=p, oid_definition=od)
        self.assertIn('otherName SAN 1.2.643.100.9',
                      p.capilite_incompatibilities())

    def test_the_badge_and_the_refusal_agree(self):
        """The whole point of sharing capilite_unsupported_ext_keys: a profile
        the UI calls incompatible must be exactly one issuance refuses."""
        p = self._profile(name_constraints_permitted='DNS:.example.org')
        self.assertTrue(p.capilite_incompatibilities())
        spec = own_ca.CertSpec(
            common_name='x', subject='/CN=x', key_alg='gost2012_256', days=1,
            ext_lines=p.to_extfile_lines(), san_dns=[], san_ip=[])
        with self.assertRaisesRegex(own_ca.OwnCAError, 'nameconstraints'):
            own_ca._reject_unsupported_spec_capilite(spec)

    def test_a_compatible_profile_is_accepted_by_issuance(self):
        p = self._profile()
        spec = own_ca.CertSpec(
            common_name='x', subject='/CN=x', key_alg='gost2012_256', days=1,
            ext_lines=p.to_extfile_lines(), san_dns=[], san_ip=[])
        own_ca._reject_unsupported_spec_capilite(spec)   # no raise


class ProfileEditorWarningTest(CATestCase):
    """U7 in the profile editor: the warning appears only when CryptoPro is on
    and the profile actually carries something unsupported."""

    def _detail(self, profile):
        # Assertions check the English source strings; the dashboard defaults
        # to Russian and LocaleMiddleware picks the language per request, so ask
        # for English through the header rather than translation.override().
        return self.client.get(
            reverse('cert_profile_detail', args=[profile.pk]),
            headers={'accept-language': 'en'},
        ).content.decode('utf-8', 'replace')

    def _marker(self):
        with tempfile.NamedTemporaryFile(delete=False) as m:
            return m.name

    def test_incompatible_profile_warns_when_cryptopro_is_on(self):
        from dashboard.tests.conftest import make_cert_profile
        p = make_cert_profile(name_constraints_permitted='DNS:.example.org')
        with override_settings(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                               OWNCA_CRYPTOPRO_ENABLED=True):
            body = self._detail(p)
        self.assertIn('Not issuable by a CryptoPro CSP-backed CA', body)
        self.assertIn('nameconstraints', body)

    def test_no_warning_without_cryptopro(self):
        from dashboard.tests.conftest import make_cert_profile
        p = make_cert_profile(name_constraints_permitted='DNS:.example.org')
        with override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker',
                               OWNCA_CRYPTOPRO_ENABLED=False):
            body = self._detail(p)
        self.assertNotIn('Not issuable by a CryptoPro CSP-backed CA', body)
        # the per-section markers are gated the same way
        self.assertNotIn('not supported by CryptoPro CSP', body)

    def test_compatible_profile_gets_no_banner_but_keeps_section_markers(self):
        from dashboard.tests.conftest import make_cert_profile
        p = make_cert_profile()
        with override_settings(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                               OWNCA_CRYPTOPRO_ENABLED=True):
            body = self._detail(p)
        self.assertNotIn('Not issuable by a CryptoPro CSP-backed CA', body)
        self.assertIn('not supported by CryptoPro CSP', body)

    def test_unsupported_sections_collapse_under_cryptopro(self):
        """They stay in the form — a profile may still serve openssl CAs, and an
        operator has to be able to remove the offending extension — but they are
        folded away so they no longer invite use the backend cannot satisfy."""
        from dashboard.tests.conftest import make_cert_profile
        p = make_cert_profile()
        with override_settings(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                               OWNCA_CRYPTOPRO_ENABLED=True):
            body = self._detail(p)
        opened = re.findall(r'<details([^>]*)>', body)
        self.assertEqual(len(opened), 3)
        self.assertTrue(all('open' not in o for o in opened), opened)
        for field in ('name_constraints_permitted',
                      'policy_constraints_require_explicit', 'extra_extensions'):
            self.assertIn(f'name="{field}"', body)

    def test_sections_stay_expanded_without_cryptopro(self):
        from dashboard.tests.conftest import make_cert_profile
        p = make_cert_profile()
        with override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker',
                               OWNCA_CRYPTOPRO_ENABLED=False):
            body = self._detail(p)
        opened = re.findall(r'<details([^>]*)>', body)
        self.assertEqual(len(opened), 3)
        self.assertTrue(all('open' in o for o in opened), opened)

    def test_oid_section_is_not_collapsed_because_san_placements_work(self):
        from dashboard.tests.conftest import make_cert_profile
        p = make_cert_profile()
        with override_settings(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                               OWNCA_CRYPTOPRO_ENABLED=True):
            body = self._detail(p)
        self.assertIn('OID fields from registry</h4>', body)
        self.assertIn('SAN otherName', body)

    def test_issue_form_payload_carries_the_problem_list(self):
        from dashboard.tests.conftest import make_cert_profile
        from dashboard.views import _profile_preview_payload
        p = make_cert_profile(name_constraints_permitted='DNS:.example.org')
        payload = _profile_preview_payload(p, self.ca)
        self.assertIn('nameconstraints', payload['capilite_problems'])


class CryptoProPageMovedTest(CATestCase):
    """The CryptoPro panels moved onto Maintenance — with the certified backend
    on, that IS the crypto backend, so it belongs with the other backend
    diagnostics. The old URL stays as the POST target and redirects."""

    def _marker(self):
        with tempfile.NamedTemporaryFile(delete=False) as m:
            return m.name

    def test_no_separate_sidebar_entry(self):
        body = self.client.get(reverse('dashboard')).content.decode('utf-8', 'replace')
        self.assertNotIn(reverse('cryptopro'), body)

    def test_old_url_redirects_to_maintenance(self):
        resp = self.client.get(reverse('cryptopro'))
        self.assertRedirects(resp, reverse('maintenance'))

    def test_panels_render_on_maintenance_when_installed(self):
        with override_settings(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                               OWNCA_CRYPTOPRO_ENABLED=True):
            body = self.client.get(
                reverse('maintenance'), headers={'accept-language': 'en'},
            ).content.decode('utf-8', 'replace')
        for panel in ('Provider status', 'DRBG gamma', 'License'):
            self.assertIn(panel, body)
        self.assertIn('license_serial', body)

    def test_panels_absent_without_cryptopro(self):
        with override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker',
                               OWNCA_CRYPTOPRO_ENABLED=False):
            body = self.client.get(
                reverse('maintenance'), headers={'accept-language': 'en'},
            ).content.decode('utf-8', 'replace')
        self.assertNotIn('Provider status', body)
        self.assertNotIn('DRBG gamma', body)
        self.assertNotIn('license_serial', body)


class ConfigurationGostP12RowTest(CATestCase):
    """The .gost.p12 toggle governs a TK-26 export that CryptoPro cannot
    produce, so the row is hidden while the backend is on — and the stored flag
    must survive a save made from that reduced form."""

    def _marker(self):
        with tempfile.NamedTemporaryFile(delete=False) as m:
            return m.name

    def _on(self):
        return override_settings(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                                 OWNCA_CRYPTOPRO_ENABLED=True)

    def _off(self):
        return override_settings(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker',
                                 OWNCA_CRYPTOPRO_ENABLED=False)

    def _body(self):
        return self.client.get(
            reverse('configuration')).content.decode('utf-8', 'replace')

    def test_row_hidden_when_cryptopro_is_on(self):
        with self._on():
            self.assertNotIn('offer_gost_p12_export', self._body())

    def test_row_present_without_cryptopro(self):
        with self._off():
            self.assertIn('offer_gost_p12_export', self._body())

    def test_saving_with_the_row_hidden_keeps_the_flag(self):
        """Regression: an unchecked-because-absent checkbox posts nothing, which
        would clear the setting on every save."""
        from dashboard.models import SystemSettings
        s = SystemSettings.get_solo()
        s.offer_gost_p12_export = True
        s.save()
        with self._on():
            self.client.post(reverse('configuration'), {'allow_gost_keys': 'on'})
        self.assertTrue(SystemSettings.get_solo().offer_gost_p12_export)

    def test_flag_still_editable_without_cryptopro(self):
        from dashboard.models import SystemSettings
        s = SystemSettings.get_solo()
        s.offer_gost_p12_export = True
        s.save()
        with self._off():
            self.client.post(reverse('configuration'), {'allow_gost_keys': 'on'})
        self.assertFalse(SystemSettings.get_solo().offer_gost_p12_export)
        with self._off():
            self.client.post(reverse('configuration'),
                             {'allow_gost_keys': 'on', 'offer_gost_p12_export': 'on'})
        self.assertTrue(SystemSettings.get_solo().offer_gost_p12_export)


class ConfigurationEnvTableTest(CATestCase):
    """The environment-variable table shows effective values, marks where each
    came from, and never prints a licence serial verbatim."""

    def _marker(self):
        with tempfile.NamedTemporaryFile(delete=False) as m:
            return m.name

    def _rows(self, **over):
        with override_settings(**over):
            resp = self.client.get(reverse('configuration'),
                                   headers={'accept-language': 'en'})
        return {r['name']: r for r in resp.context['env_rows']}, \
            resp.content.decode('utf-8', 'replace')

    def test_core_variables_carry_their_effective_value(self):
        rows, _body = self._rows()
        self.assertEqual(rows['OWNCA_STORAGE_DIR']['value'],
                         str(settings.OWNCA_STORAGE_DIR))
        self.assertEqual(rows['OWNCA_DEFAULT_CA_DAYS']['value'],
                         settings.OWNCA_DEFAULT_CA_DAYS)

    def test_source_separates_environment_from_default(self):
        import os
        rows, _body = self._rows()
        for name, row in rows.items():
            expected = 'env' if os.environ.get(name) is not None else 'default'
            self.assertEqual(row['source'], expected, name)

    def test_cryptopro_rows_only_on_an_image_that_has_it(self):
        rows, _body = self._rows(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker')
        self.assertNotIn('OWNCA_CRYPTOPRO_ROOT', rows)
        rows, _body = self._rows(OWNCA_CRYPTOPRO_MARKER=self._marker())
        self.assertIn('OWNCA_CRYPTOPRO_ROOT', rows)
        self.assertIn('OWNCA_CRYPTOPRO_SHIM_BIN', rows)

    def test_licence_serial_is_masked_and_never_rendered_in_full(self):
        serial = 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'
        rows, body = self._rows(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                                OWNCA_CRYPTOPRO_LICENSE=serial)
        self.assertNotEqual(rows['OWNCA_CRYPTOPRO_LICENSE']['value'], serial)
        self.assertIn('****', rows['OWNCA_CRYPTOPRO_LICENSE']['value'])
        self.assertNotIn(serial, body)

    def test_enabled_flag_reflects_what_settings_resolved(self):
        """settings.py forces the flag off without the build marker; the table
        must show what took effect, not what was requested."""
        rows, _body = self._rows(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                                 OWNCA_CRYPTOPRO_ENABLED=False)
        self.assertFalse(rows['OWNCA_CRYPTOPRO_ENABLED']['value'])

    def test_table_is_rendered_with_a_value_column(self):
        _rows, body = self._rows()
        self.assertIn('Current value', body)
        self.assertIn(str(settings.OWNCA_STORAGE_DIR), body)


class MaintenancePageTest(CATestCase):
    """The maintenance page describes the openssl leg. With CryptoPro on that
    leg no longer signs, so the detail is folded away and the missing-engine
    warning stops claiming something untrue."""

    def _marker(self):
        with tempfile.NamedTemporaryFile(delete=False) as m:
            return m.name

    def _body(self, **over):
        with override_settings(**over):
            return self.client.get(
                reverse('maintenance'), headers={'accept-language': 'en'},
            ).content.decode('utf-8', 'replace')

    def test_openssl_panel_shown_when_openssl_is_the_backend(self):
        body = self._body(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker',
                          OWNCA_CRYPTOPRO_ENABLED=False)
        self.assertIn('Crypto backend', body)
        self.assertIn('openssl version', body)
        self.assertIn('GOST engine loaded', body)

    def test_openssl_panel_hidden_when_cryptopro_signs(self):
        """openssl signs nothing then — a panel headed "Crypto backend" that
        described it would name the wrong backend."""
        body = self._body(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                          OWNCA_CRYPTOPRO_ENABLED=True)
        self.assertNotIn('openssl version', body)
        self.assertNotIn('GOST engine loaded', body)

    def test_missing_engine_warning_only_where_it_is_true(self):
        with mock.patch.object(own_ca, 'gost_engine_loaded', return_value=False):
            off = self._body(OWNCA_CRYPTOPRO_MARKER='/nonexistent/marker',
                             OWNCA_CRYPTOPRO_ENABLED=False)
            on = self._body(OWNCA_CRYPTOPRO_MARKER=self._marker(),
                            OWNCA_CRYPTOPRO_ENABLED=True)
        self.assertIn('Only RSA algorithms will work', off)
        self.assertNotIn('Only RSA algorithms will work', on)

    def test_openssl_probe_runs_once_per_render(self):
        """The summary and the dump come from one call — the page should not
        shell out to openssl twice just to show a heading."""
        with mock.patch.object(own_ca, 'openssl_version',
                               return_value='OpenSSL 3.5.0\nbuilt on: x') as probe:
            self._body()
        self.assertEqual(probe.call_count, 1)


class GammaRowLabelTest(TestCase):
    """Rows are labelled with the pool's relative name: the directory is stated
    once above, and the full path does not fit the label column."""

    def test_rel_is_the_pool_name(self):
        d = tempfile.mkdtemp()
        with override_settings(OWNCA_CRYPTOPRO_GAMMA_DIR=d):
            files = cryptopro.gamma_status().files
        self.assertEqual([f.rel for f in files], list(cryptopro.GAMMA_POOL_FILES))
        for f in files:
            self.assertTrue(f.path.endswith(f.rel))
            self.assertNotEqual(f.path, f.rel)
