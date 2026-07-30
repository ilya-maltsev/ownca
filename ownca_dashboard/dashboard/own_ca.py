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
OwnCA — Certificate Authority backend (GOST + RSA).

Thin wrapper over the system `openssl` binary, which the dev_env Dockerfile builds
with gost-engine loaded via OPENSSL_CONF=/etc/ssl/openssl.cnf. This module:

- builds per-CA OpenSSL config files
- generates GOST or RSA private keys
- creates self-signed root CAs and signs intermediate CAs
- signs end-entity certificates from a CSR (or generates the CSR server-side)
- revokes certificates and emits CRLs
- parses x509 metadata (subject/issuer/serial/dates/fingerprint) from PEM

Storage layout (under settings.OWNCA_STORAGE_DIR):

    cas/<uuid>/
        ca.crt              PEM CA cert
        ca.key              PEM CA private key (mode 0600)
        openssl.cnf         per-CA openssl config (used for `openssl ca` ops)
        index.txt           openssl ca database
        index.txt.attr      openssl ca database attributes
        serial              next cert serial (hex)
        crlnumber           next CRL number (hex)
        crl.pem             latest generated CRL
        newcerts/<SERIAL>.pem  copies of signed certs by serial
    certs/<uuid>/
        cert.pem            PEM cert
        key.pem             PEM private key (mode 0600), present only if generated server-side
        csr.pem             PEM CSR (always written)
    crls/
        <ca_name>.crl       published copy of each CA's CRL, written by the
                            "Rebuild all CRLs" maintenance action (see export_crl)

All paths are computed from the model instance via .storage_dir / .cert_path /
.key_path / .csr_path / .crl_path so the database row is the source of truth.

This module deliberately raises OwnCAError on any failure so the view layer can
surface a single error type to the user.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from django.conf import settings


logger = logging.getLogger('dashboard')


class OwnCAError(Exception):
    """Raised on any underlying openssl / filesystem failure."""


# ---------------------------------------------------------------------------
# openssl invocation
# ---------------------------------------------------------------------------

def _openssl_bin() -> str:
    return getattr(settings, 'OWNCA_OPENSSL_BIN', 'openssl')


def _run(args: list[str], *, input_bytes: bytes | None = None, cwd: Path | None = None) -> str:
    """Run openssl with the given args, return stdout (text). Raise on failure."""
    cmd = [_openssl_bin()] + args
    try:
        proc = subprocess.run(
            cmd,
            input=input_bytes,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError as e:
        raise OwnCAError(f'openssl binary not found: {e}') from e
    except subprocess.TimeoutExpired as e:
        raise OwnCAError(f'openssl timed out: {" ".join(cmd)}') from e

    if proc.returncode != 0:
        stderr = proc.stderr.decode('utf-8', errors='replace').strip()
        stdout = proc.stdout.decode('utf-8', errors='replace').strip()
        raise OwnCAError(
            f'openssl {args[0] if args else "?"} failed (exit {proc.returncode}): '
            f'{stderr or stdout or "no output"}'
        )
    return proc.stdout.decode('utf-8', errors='replace')


def openssl_version() -> str:
    """Return `openssl version -a` output, or an error string."""
    try:
        return _run(['version', '-a']).strip()
    except OwnCAError as e:
        return f'(unavailable: {e})'


def gost_engine_loaded() -> bool:
    """Best-effort check that the gost engine is reachable to openssl."""
    try:
        out = _run(['engine', '-t', 'gost'])
    except OwnCAError:
        return False
    return '[ available ]' in out or 'gost' in out.lower()


# ---------------------------------------------------------------------------
# CryptoPro CSP backend routing
#
# A GOST CA can be backed by CryptoPro CSP (certified) instead of
# openssl+gost-engine. Its private key then lives in a CryptoPro *container*
# (never a PEM), so `openssl ca` cannot sign for it — the WHOLE lifecycle of
# such a CA (root, sign, issue, CRL, p12) must go through the ownca_capi shim.
# Which backend a CA uses is recorded on disk in `cas/<uuid>/backend` at
# creation time (disk = source of truth, matching this module's philosophy).
# ---------------------------------------------------------------------------

def _cryptopro_active_for(key_alg: str) -> bool:
    """True when new GOST CAs should be created on the CryptoPro backend."""
    if not key_alg.startswith('gost2012'):
        return False
    from . import cryptopro
    return cryptopro.enabled()


def _capi_shim() -> str:
    return getattr(settings, 'OWNCA_CRYPTOPRO_SHIM_BIN', '/opt/ownca/bin/ownca_capi')


def _run_capi(args: list[str]) -> str:
    """Run the ownca_capi shim; return stdout. Raise OwnCAError on failure."""
    cmd = [_capi_shim()] + args
    try:
        proc = subprocess.run(cmd, capture_output=True, check=False, timeout=120)
    except FileNotFoundError as e:
        raise OwnCAError(f'ownca_capi shim not found: {e}') from e
    except subprocess.TimeoutExpired:
        raise OwnCAError(f'ownca_capi timed out: {" ".join(cmd)}')
    if proc.returncode != 0:
        stderr = proc.stderr.decode('utf-8', errors='replace').strip()
        stdout = proc.stdout.decode('utf-8', errors='replace').strip()
        raise OwnCAError(
            f'ownca_capi {args[0] if args else "?"} failed '
            f'(exit {proc.returncode}): {stderr or stdout or "no output"}'
        )
    return proc.stdout.decode('utf-8', errors='replace')


def _capi_ca_container(ca_uuid: str) -> str:
    """The CA's ACTUAL CryptoPro container name — read from the backend marker
    (authoritative: an imported CA's container is named by PFXImportCertStore,
    e.g. 'pfx-<guid>', not by our ownca_ca_<hex> convention). Falls back to the
    deterministic name for markers written before this field existed."""
    _backend, container = read_ca_backend(ca_uuid)
    return container or _capi_container_for(ca_uuid)


def _capi_container_for(ca_uuid: str) -> str:
    """Deterministic CryptoPro container name for a CA (HDIMAGE-safe)."""
    return 'ownca_ca_' + str(ca_uuid).replace('-', '')


def _der_to_pem(der: bytes, label: str) -> bytes:
    """Wrap DER bytes in a PEM armor (base64, 64-col). Pure encoding — used on
    the CryptoPro path so no openssl call touches the GOST material."""
    import base64
    b64 = base64.encodebytes(der).decode('ascii')
    body = ''.join(b64.split('\n'))
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return (f'-----BEGIN {label}-----\n' + '\n'.join(lines) +
            f'\n-----END {label}-----\n').encode('ascii')


def _der_file_to_pem(der_path: Path, label: str) -> bytes:
    return _der_to_pem(der_path.read_bytes(), label)


# --- extspec (structured X.509 extensions for the CAPILite shim) -----------
# The shim can't reuse openssl's cnf extension engine, so Python emits a simple
# key=value "extspec" file that the shim encodes via CryptEncodeObject.

_KU_BIT = {   # name -> (byte index, mask)  per RFC 5280 KeyUsage bit order
    'digitalSignature': (0, 0x80), 'nonRepudiation': (0, 0x40),
    'keyEncipherment': (0, 0x20), 'dataEncipherment': (0, 0x10),
    'keyAgreement': (0, 0x08), 'keyCertSign': (0, 0x04),
    'cRLSign': (0, 0x02), 'encipherOnly': (0, 0x01),
    'decipherOnly': (1, 0x80),
}
_EKU_OID = {
    'serverAuth': '1.3.6.1.5.5.7.3.1', 'clientAuth': '1.3.6.1.5.5.7.3.2',
    'codeSigning': '1.3.6.1.5.5.7.3.3', 'emailProtection': '1.3.6.1.5.5.7.3.4',
    'timeStamping': '1.3.6.1.5.5.7.3.8', 'OCSPSigning': '1.3.6.1.5.5.7.3.9',
    'ipsecEndSystem': '1.3.6.1.5.5.7.3.5', 'ipsecTunnel': '1.3.6.1.5.5.7.3.6',
    'ipsecUser': '1.3.6.1.5.5.7.3.7',
    'msSmartcardLogin': '1.3.6.1.4.1.311.20.2.2',
}


def _ku_hex_unused(names: list[str]) -> tuple[str, int]:
    """Turn KeyUsage bit names into (hex-bytes, unused-bit-count) for the shim."""
    buf = [0, 0]
    for nm in names:
        bit = _KU_BIT.get(nm.strip())
        if bit:
            buf[bit[0]] |= bit[1]
    nbytes = 2 if buf[1] else 1
    raw = bytes(buf[:nbytes])
    # trim trailing zero byte already handled; compute unused bits in last byte
    last = raw[-1]
    unused = 0
    if last:
        while not (last >> unused) & 1:
            unused += 1
    else:
        unused = 8
    return raw.hex(), unused


def _eku_to_oids(tokens: list[str]) -> list[str]:
    out = []
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        out.append(_EKU_OID.get(t, t))  # pass raw OIDs through
    return out


def _ip_to_hex(ip: str) -> str:
    """Dotted IPv4 (or bare IPv6) -> hex octets for a SAN IPAddress. Best-effort;
    returns '' on anything unparseable so the entry is skipped."""
    ip = ip.strip()
    try:
        if ':' in ip:
            import ipaddress
            return ipaddress.IPv6Address(ip).packed.hex()
        parts = ip.split('.')
        if len(parts) == 4:
            return bytes(int(p) for p in parts).hex()
    except (ValueError, ipaddress.AddressValueError):
        return ''
    return ''


# GeneralName type prefixes the CAPILite shim can encode (issuerAltName). The
# openssl path accepts everything openssl does; anything outside this set must
# be refused on the CryptoPro backend rather than dropped.
_GENERAL_NAME_KINDS = {'dns': 'dns', 'email': 'email', 'uri': 'uri', 'ip': 'ip'}


def _split_general_names(entries: list) -> tuple[dict, list]:
    """Split openssl-style GeneralName strings ("DNS:host", "email:a@b",
    "URI:http://x", "IP:10.0.0.1") into the typed lists the extspec wants.

    Returns ``(buckets, unsupported)`` — anything whose type the shim cannot
    encode (dirName, otherName, RID, …) lands in ``unsupported`` so the caller
    can refuse instead of silently dropping it."""
    buckets: dict[str, list[str]] = {'dns': [], 'email': [], 'uri': [], 'ip': []}
    unsupported: list[str] = []
    for raw in (entries or []):
        if not raw:
            continue
        entry = str(raw).strip()
        if not entry:
            continue
        prefix, sep, value = entry.partition(':')
        kind = _GENERAL_NAME_KINDS.get(prefix.strip().lower()) if sep else None
        if not kind or not value.strip():
            unsupported.append(entry)
            continue
        buckets[kind].append(value.strip())
    return buckets, unsupported


def _general_names_or_raise(entries: list, what: str) -> dict:
    """`_split_general_names` that refuses unencodable entries outright."""
    buckets, unsupported = _split_general_names(entries)
    if unsupported:
        raise OwnCAError(
            f'This CA is backed by CryptoPro CSP; these {what} entries use a '
            f'name type this backend cannot encode: {", ".join(unsupported)}. '
            'Use DNS:, email:, URI: or IP: entries, or an openssl-backed CA.'
        )
    return buckets


def _parse_profile_ext_lines(ext_lines: list[str]) -> dict:
    """Pull the structured bits the shim understands out of the rendered openssl
    ext lines (basicConstraints / keyUsage / extendedKeyUsage / SKI / AKI).
    Advanced lines (policies, name constraints, raw extras) are ignored — they
    are unsupported on the CryptoPro backend and rejected earlier.

    ``want_ski`` / ``want_aki`` / ``aki_issuer`` mirror the profile's
    subjectKeyIdentifier / authorityKeyIdentifier toggles, following OpenSSL
    3.x semantics so both backends agree: an ABSENT line still yields the
    extension (openssl `ca` adds SKI/AKI on its own), and only an explicit
    ``= none`` suppresses it."""
    out = {'bc_ca': False, 'bc_pathlen': -1, 'ku': [], 'ku_critical': False,
           'eku': [], 'eku_critical': False,
           'want_ski': True, 'want_aki': True, 'aki_issuer': False}
    for raw in ext_lines:
        line = raw.strip()
        low = line.lower()
        if low.startswith('basicconstraints'):
            val = line.split('=', 1)[1] if '=' in line else ''
            out['bc_ca'] = 'ca:true' in val.lower()
            m = re.search(r'pathlen:\s*(\d+)', val)
            if m:
                out['bc_pathlen'] = int(m.group(1))
        elif low.startswith('keyusage'):
            val = line.split('=', 1)[1] if '=' in line else ''
            out['ku_critical'] = 'critical' in val.lower()
            out['ku'] = [t.strip() for t in val.split(',') if t.strip() and t.strip().lower() != 'critical']
        elif low.startswith('extendedkeyusage'):
            val = line.split('=', 1)[1] if '=' in line else ''
            out['eku_critical'] = 'critical' in val.lower()
            out['eku'] = [t.strip() for t in val.split(',') if t.strip() and t.strip().lower() != 'critical']
        elif low.startswith('subjectkeyidentifier'):
            val = (line.split('=', 1)[1] if '=' in line else '').strip().lower()
            out['want_ski'] = val != 'none'
        elif low.startswith('authoritykeyidentifier'):
            val = (line.split('=', 1)[1] if '=' in line else '').strip().lower()
            out['want_aki'] = val != 'none'
            # "keyid:always, issuer:always" — the issuer half adds
            # authorityCertIssuer + authorityCertSerialNumber (RFC 5280 §4.2.1.1)
            out['aki_issuer'] = 'issuer' in val
    return out


# Extension keys the CryptoPro shim can encode. Anything else in a profile is
# rejected loudly (never silently dropped) — see _reject_unsupported_spec_capilite.
# SKI/AKI are listed because the capilite path always encodes them (shim ski=1/
# aki=1), so a profile requesting them is satisfied, not ignored.
_CAPI_SUPPORTED_EXT_KEYS = {
    'basicconstraints', 'keyusage', 'extendedkeyusage',
    'subjectkeyidentifier', 'authoritykeyidentifier',
}


def capilite_unsupported_ext_keys(ext_lines: list) -> list[str]:
    """Extension keys in rendered openssl ext lines the CryptoPro backend
    cannot encode.

    Single source of truth for two callers that must never disagree: the
    issuance refusal below, and the UI badge that warns an operator BEFORE they
    pick such a profile. Deduplicated, order preserved.
    """
    unsupported: list[str] = []
    for raw in (ext_lines or []):
        line = str(raw).strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):          # policy section blocks etc.
            unsupported.append(f'profile section {line}')
            continue
        key = line.split('=', 1)[0].strip().lower()
        if key not in _CAPI_SUPPORTED_EXT_KEYS:
            unsupported.append(key)
    return list(dict.fromkeys(unsupported))


def _reject_unsupported_spec_capilite(spec: 'CertSpec') -> None:
    """The CryptoPro backend encodes a fixed set of extensions (BC/KU/EKU/SKI/
    AKI/SAN dns-ip-email-uri/CDP/AIA/SIA/freshestCRL/issuerAltName). A profile
    or request carrying anything beyond that must fail loudly — silently
    dropping an extension the profile promises would misissue."""
    unsupported: list[str] = []
    if spec.san_other:
        unsupported.append('otherName SAN entries')
    _general_names_or_raise(spec.issuer_alt_names, 'issuerAltName')
    unsupported += capilite_unsupported_ext_keys(spec.ext_lines)
    if unsupported:
        uniq = ', '.join(dict.fromkeys(unsupported))
        raise OwnCAError(
            'This CA is backed by CryptoPro CSP; the following requested '
            f'extensions are not supported on this backend: {uniq}. Remove '
            'them from the certificate profile / request, or use an '
            'openssl-backed CA.'
        )


def _write_extspec(path: Path, *, is_ca: bool, pathlen: int,
                   ku: list[str], ku_critical: bool,
                   eku: list[str], eku_critical: bool,
                   san_dns=None, san_ip=None, san_email=None, san_uri=None,
                   cdp=None, aia_ca=None, aia_ocsp=None,
                   sia_repo=None, freshest_crl=None, issuer_alt_names=None,
                   want_ski=True, want_aki=True,
                   aki_issuer_dn='', aki_issuer_serial='') -> None:
    lines = ['bc=1', f'bc_ca={1 if is_ca else 0}', 'bc_critical=1']
    if pathlen is not None and pathlen >= 0:
        lines.append(f'bc_pathlen={pathlen}')
    if ku:
        ku_hex, unused = _ku_hex_unused(ku)
        lines += [f'ku_hex={ku_hex}', f'ku_unused={unused}',
                  f'ku_critical={1 if ku_critical else 0}']
    for oid in _eku_to_oids(eku or []):
        lines.append(f'eku={oid}')
    if eku:
        lines.append(f'eku_critical={1 if eku_critical else 0}')
    if want_ski:
        lines.append('ski=1')
    if want_aki:
        lines.append('aki=1')
        # Only present for a profile asking `issuer:always`; without them the
        # shim emits the keyid-only AKI.
        if aki_issuer_dn:
            lines.append(f'aki_issuer_dn={aki_issuer_dn}')
        if aki_issuer_serial:
            lines.append(f'aki_issuer_serial={aki_issuer_serial}')
    for d in (san_dns or []):
        lines.append(f'san_dns={d}')
    for ip in (san_ip or []):
        h = _ip_to_hex(ip)
        if h:
            lines.append(f'san_ip={h}')
    for e in (san_email or []):
        lines.append(f'san_email={e}')
    for u in (san_uri or []):
        lines.append(f'san_uri={u}')
    for c in ([cdp] if isinstance(cdp, str) else (cdp or [])):
        if c:
            lines.append(f'cdp={c}')
    for a in ([aia_ca] if isinstance(aia_ca, str) else (aia_ca or [])):
        if a:
            lines.append(f'aia_ca={a}')
    for o in ([aia_ocsp] if isinstance(aia_ocsp, str) else (aia_ocsp or [])):
        if o:
            lines.append(f'aia_ocsp={o}')
    for r in ([sia_repo] if isinstance(sia_repo, str) else (sia_repo or [])):
        if r:
            lines.append(f'sia_repo={r}')
    for fc in ([freshest_crl] if isinstance(freshest_crl, str) else (freshest_crl or [])):
        if fc:
            lines.append(f'freshest_crl={fc}')
    # issuerAltName arrives as openssl GeneralName strings; the shim wants them
    # split by type, so callers pass the already-bucketed dict.
    ian = issuer_alt_names or {}
    for kind in ('dns', 'email', 'uri'):
        for v in ian.get(kind, []):
            lines.append(f'ian_{kind}={v}')
    for v in ian.get('ip', []):
        h = _ip_to_hex(v)
        if h:
            lines.append(f'ian_ip={h}')
    path.write_text('\n'.join(lines) + '\n')


def _openssl_subj_to_x500(subj: str) -> str:
    """Convert an openssl `-subj` DN ("/C=RU/O=Org/CN=Name") to the X.500 comma
    form CryptoPro's CertStrToNameA expects ("C=RU, O=Org, CN=Name"). A DN
    already in comma form is returned unchanged."""
    s = subj.strip()
    if not s.startswith('/'):
        return s
    parts = [p for p in s.split('/') if p]
    return ', '.join(parts)


def _write_backend(ca_dir: Path, backend: str) -> None:
    """Record a CA's crypto backend on disk. `backend` is 'openssl' or
    'capilite:<container>'."""
    (ca_dir / 'backend').write_text(backend + '\n')


def read_ca_backend(ca_uuid: str) -> tuple[str, str]:
    """Return (backend, container) for a CA, read from its on-disk marker.
    backend is 'openssl' or 'capilite'; container is '' for openssl. A CA
    predating this feature (no marker) is treated as 'openssl'."""
    ca_dir = _storage_root() / 'cas' / str(ca_uuid)
    marker = ca_dir / 'backend'
    if not marker.exists():
        return 'openssl', ''
    val = marker.read_text().strip()
    if val.startswith('capilite:'):
        return 'capilite', val.split(':', 1)[1]
    return 'openssl', ''


def _capi_serial_hex() -> str:
    """A positive, even-length, non-zero serial as hex (8 random bytes)."""
    sn = bytearray(secrets.token_bytes(8))
    sn[0] = (sn[0] & 0x7F) | 0x40
    sn[-1] |= 0x01
    return sn.hex()


def _capi_cert_container_for(cert_uuid: str) -> str:
    return 'ownca_crt_' + str(cert_uuid).replace('-', '')


def _capi_paramset_args(key_alg: str, paramset: str) -> list[str]:
    """`genkey --paramset` args for a GOST key. Validated against what the
    provider actually supports, so an unusable choice fails before a container
    is created rather than being silently replaced by the provider default."""
    valid = capi_supported_paramsets(key_alg)
    if not valid:
        return []
    ps = (paramset or DEFAULT_GOST_PARAMSET).strip()
    if ps not in valid:
        raise OwnCAError(
            f'invalid paramset {ps!r} for {key_alg}; this CryptoPro provider '
            f'supports {", ".join(valid)}'
        )
    return ['--paramset', ps]


def _store_x500_subject(ca_dir: Path, x500: str) -> None:
    (ca_dir / 'subject_x500').write_text(x500 + '\n')


def _read_x500_subject(ca_uuid: str) -> str:
    """The exact X.500 issuer string used when the CA was created (byte-stable
    DN for chain building). Falls back to converting the parsed cert subject."""
    ca_dir = _storage_root() / 'cas' / str(ca_uuid)
    f = ca_dir / 'subject_x500'
    if f.exists():
        return f.read_text().strip()
    return _openssl_subj_to_x500(parse_cert(ca_dir / 'ca.crt').get('subject', ''))


def _write_ca_crl_days(ca_dir: Path, profile_vars: Optional[dict]) -> None:
    """Record a CryptoPro CA's CRL validity next to its other on-disk metadata.
    The openssl backend keeps the same value in its per-CA openssl.cnf, which a
    CryptoPro CA has no reason to own."""
    days = (profile_vars or {}).get('default_crl_days', DEFAULT_CRL_DAYS)
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = DEFAULT_CRL_DAYS
    (ca_dir / 'crl_days').write_text(f'{days}\n')


def _ca_crl_days(ca_uuid: str) -> int:
    """CRL validity in days for a CA. CAs created before this was recorded (and
    every imported CA) fall back to the module default — the same value their
    openssl.cnf would have carried."""
    f = _storage_root() / 'cas' / str(ca_uuid) / 'crl_days'
    try:
        days = int(f.read_text().strip())
    except (OSError, ValueError):
        return DEFAULT_CRL_DAYS
    return days if days > 0 else DEFAULT_CRL_DAYS


def _store_x500_issuer(ca_dir: Path, x500: str) -> None:
    (ca_dir / 'issuer_x500').write_text(x500 + '\n')


def _read_x500_issuer(ca_uuid: str) -> str:
    """The X.500 DN of the CA certificate's OWN issuer — its parent's subject,
    or its own for a self-signed root. Needed for authorityKeyIdentifier's
    authorityCertIssuer, which identifies the CA's certificate rather than the
    certificate being signed. Falls back to the parsed cert for CAs predating
    the marker (imports included)."""
    ca_dir = _storage_root() / 'cas' / str(ca_uuid)
    f = ca_dir / 'issuer_x500'
    if f.exists():
        return f.read_text().strip()
    return _openssl_subj_to_x500(parse_cert(ca_dir / 'ca.crt').get('issuer', ''))


def _ca_cert_serial_hex(ca_uuid: str) -> str:
    """The CA certificate's own serial as even-length hex — the other half of an
    `issuer:always` authorityKeyIdentifier."""
    serial = parse_cert(_storage_root() / 'cas' / str(ca_uuid) / 'ca.crt'
                        ).get('serial_hex', '')
    serial = serial.replace(':', '').replace(' ', '').strip()
    return ('0' + serial) if len(serial) % 2 else serial


def _capi_alg_for(ca_uuid: str) -> str:
    """The CA's GOST key algorithm (gost2012_256/512), recorded at creation."""
    ca_dir = _storage_root() / 'cas' / str(ca_uuid)
    f = ca_dir / 'key_alg'
    if f.exists():
        return f.read_text().strip()
    return detect_cert_key_alg(ca_dir / 'ca.crt') or 'gost2012_256'


# ---------------------------------------------------------------------------
# storage layout
# ---------------------------------------------------------------------------

def _storage_root() -> Path:
    root = Path(getattr(settings, 'OWNCA_STORAGE_DIR', '/var/lib/ownca'))
    root.mkdir(parents=True, exist_ok=True)
    (root / 'cas').mkdir(exist_ok=True)
    (root / 'certs').mkdir(exist_ok=True)
    return root


def _ensure_dir(p: Path, mode: int = 0o755) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, mode)
    except OSError:
        pass


def _write_secret(path: Path, content: bytes | str) -> None:
    """Write a private key with mode 0600."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    path.write_bytes(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# per-CA openssl.cnf
# ---------------------------------------------------------------------------

_OPENSSL_CNF_TEMPLATE = """\
# Per-CA OpenSSL config for OwnCA — DO NOT EDIT BY HAND.

[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = {ca_dir}
certs            = $dir
crl_dir          = $dir
new_certs_dir    = $dir/newcerts
database         = $dir/index.txt
serial           = $dir/serial
crlnumber        = $dir/crlnumber
certificate      = $dir/ca.crt
private_key      = $dir/ca.key
crl              = $dir/crl.pem
default_md       = {default_md}
default_days     = {default_days}
default_crl_days = {default_crl_days}
preserve         = no
policy           = policy_default
email_in_dn      = no
unique_subject   = {unique_subject}
copy_extensions  = {copy_extensions}
crl_extensions   = crl_ext

[ policy_default ]
countryName             = {policy_country_name}
stateOrProvinceName     = {policy_state_or_province_name}
localityName            = {policy_locality_name}
organizationName        = {policy_organization_name}
organizationalUnitName  = {policy_organizational_unit_name}
commonName              = {policy_common_name}
emailAddress            = {policy_email_address}

[ req ]
default_md         = {default_md}
prompt             = no
distinguished_name = req_dn
x509_extensions    = v3_ca

[ req_dn ]
CN = placeholder

[ v3_ca ]
basicConstraints       = critical, CA:TRUE{pathlen}
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

# RFC 5280 §5.2 — extensions on the CRL itself. The crlNumber is auto-emitted
# by openssl when the [crl_ext] section is referenced, sourced from the
# crlnumber file declared above.
[ crl_ext ]
authorityKeyIdentifier = keyid:always

"""


def _md_for_alg(key_alg: str) -> Optional[str]:
    """Return the digest name to pass on the openssl command line, or None
    for algorithms that have a fixed/internal digest (Ed25519)."""
    if key_alg == 'gost2012_256':
        return 'md_gost12_256'
    if key_alg == 'gost2012_512':
        return 'md_gost12_512'
    if key_alg == 'ed25519':
        return None
    if key_alg == 'ec:P-384':
        return 'sha384'
    return 'sha256'


def _default_md_for_cnf(key_alg: str) -> str:
    """``default_md`` value for the per-CA ``openssl.cnf``. For Ed25519 we
    use the literal string ``default`` which tells openssl to pick the
    algorithm's natural digest (Ed25519 has none — it signs the message
    directly)."""
    md = _md_for_alg(key_alg)
    return md if md else 'default'


def _md_args(key_alg: str) -> list[str]:
    """Return the `-<digest>` arg list for `openssl req` (where the digest
    must match the SUBJECT key being used to sign the CSR), or an empty list
    when the algorithm has no external digest.

    NOTE: this is for `req`, where you sign with your OWN key. For `openssl
    ca` (signing someone else's CSR), the digest must match the CA's key —
    not the subject's — so leave it unset and let openssl read `default_md`
    from the per-CA openssl.cnf instead.
    """
    md = _md_for_alg(key_alg)
    return ['-' + md] if md else []


# How long a freshly generated CRL stays valid. Shared by both backends: the
# openssl path bakes it into the per-CA openssl.cnf, the CryptoPro path records
# it in `cas/<uuid>/crl_days` and passes it to the shim. Keeping one constant is
# the point — the two used to disagree (30 vs a hardcoded 7).
DEFAULT_CRL_DAYS = 30

_DEFAULT_CNF_VARS = {
    'default_days': 365,
    'default_crl_days': DEFAULT_CRL_DAYS,
    'unique_subject': 'no',
    # 'none' = strict profile priority: CSR-requested extensions (KU, EKU, SAN,
    # basicConstraints…) are dropped; only the extfile chosen by the issue flow
    # is baked into the final certificate.
    'copy_extensions': 'none',
    'policy_country_name': 'optional',
    'policy_state_or_province_name': 'optional',
    'policy_locality_name': 'optional',
    'policy_organization_name': 'optional',
    'policy_organizational_unit_name': 'optional',
    'policy_common_name': 'supplied',
    'policy_email_address': 'optional',
}


def _write_openssl_cnf(
    ca_dir: Path,
    key_alg: str,
    *,
    pathlen: Optional[int] = None,
    profile_vars: Optional[dict] = None,
) -> Path:
    """Render the per-CA openssl.cnf from the template + optional overrides.

    ``profile_vars`` overrides the keys in ``_DEFAULT_CNF_VARS`` when supplied.
    """
    cnf = ca_dir / 'openssl.cnf'
    pathlen_str = f', pathlen:{pathlen}' if pathlen is not None else ''
    vars_ = dict(_DEFAULT_CNF_VARS)
    if profile_vars:
        vars_.update(profile_vars)
    cnf.write_text(_OPENSSL_CNF_TEMPLATE.format(
        ca_dir=str(ca_dir),
        default_md=_default_md_for_cnf(key_alg),
        pathlen=pathlen_str,
        **vars_,
    ))
    return cnf


def export_openssl_cnf(
    ca_uuid: str,
    key_alg: str,
    *,
    pathlen: Optional[int] = None,
    profile_vars: Optional[dict] = None,
) -> Path:
    """Re-render the openssl.cnf for an EXISTING CA on disk. Used after a
    profile is edited so the next openssl ca call picks up new values."""
    ca_dir = _storage_root() / 'cas' / ca_uuid
    if not ca_dir.exists():
        raise OwnCAError(f'CA {ca_uuid} storage directory missing')
    return _write_openssl_cnf(
        ca_dir, key_alg, pathlen=pathlen, profile_vars=profile_vars,
    )


def _init_ca_db(ca_dir: Path) -> None:
    """Create the openssl `ca` bookkeeping files if missing."""
    _ensure_dir(ca_dir / 'newcerts')
    index = ca_dir / 'index.txt'
    if not index.exists():
        index.write_text('')
    attr = ca_dir / 'index.txt.attr'
    if not attr.exists():
        attr.write_text('unique_subject = no\n')
    serial = ca_dir / 'serial'
    if not serial.exists():
        serial.write_text(secrets.token_hex(8).upper() + '\n')
    crlnum = ca_dir / 'crlnumber'
    if not crlnum.exists():
        crlnum.write_text('1000\n')


# ---------------------------------------------------------------------------
# key generation
# ---------------------------------------------------------------------------

# Valid GOST R 34.10-2012 parameter sets, per gost-engine. 256-bit keys accept
# CryptoPro sets A/B/C plus the exchange sets XchA/XchB (labelled XA/XB here to
# match the CLI). 512-bit keys only have A/B/C.
GOST_PARAMSET_CHOICES_256 = ['A', 'B', 'C', 'XA', 'XB']
GOST_PARAMSET_CHOICES_512 = ['A', 'B', 'C']
DEFAULT_GOST_PARAMSET = 'A'


def gost_paramset_choices(key_alg: str) -> list[str]:
    """Return the list of valid paramsets for a GOST key_alg, or []."""
    if key_alg == 'gost2012_256':
        return list(GOST_PARAMSET_CHOICES_256)
    if key_alg == 'gost2012_512':
        return list(GOST_PARAMSET_CHOICES_512)
    return []


# Short paramset name -> OID, per GOST key family. Mirrors paramset_oid_for()
# in the shim; the two must agree or the provider capability check below would
# compare against the wrong identifiers.
GOST_PARAMSET_OIDS = {
    'gost2012_256': {
        'A': '1.2.643.2.2.35.1', 'B': '1.2.643.2.2.35.2', 'C': '1.2.643.2.2.35.3',
        'XA': '1.2.643.2.2.36.0', 'XB': '1.2.643.2.2.36.1',
    },
    'gost2012_512': {
        'A': '1.2.643.7.1.2.1.2.1', 'B': '1.2.643.7.1.2.1.2.2',
        'C': '1.2.643.7.1.2.1.2.3',
    },
}

# A provider's capability list is fixed for the life of the process.
_capi_paramset_cache: dict[str, list[str]] = {}


def capi_supported_paramsets(key_alg: str) -> list[str]:
    """The paramsets the CryptoPro provider actually offers, as our short names.

    GOST_PARAMSET_CHOICES_* describe what gost-engine supports; the certified
    provider has its own list (PP_ENUM_SIGNATUREOID). Offering a set the
    provider will refuse is a dead option in the UI, so ask instead of assuming.

    Best-effort: if the shim cannot answer, the static list is returned so the
    issue form keeps working — a genuinely unsupported set then fails loudly at
    `genkey` rather than being silently swapped for the default.
    """
    static = gost_paramset_choices(key_alg)
    if not static:
        return []
    cached = _capi_paramset_cache.get(key_alg)
    if cached is not None:
        return list(cached)
    try:
        import json
        out = _run_capi(['paramsets', '--alg', key_alg])
        oids = set(json.loads(out.strip().splitlines()[-1]).get('oids') or [])
    except (OwnCAError, ValueError, IndexError, KeyError) as e:
        logger.warning('cannot enumerate CryptoPro paramsets for %s: %s', key_alg, e)
        return static
    names = [n for n in static if GOST_PARAMSET_OIDS[key_alg][n] in oids]
    if not names:
        # Nothing in common is not a real provider state; treat it as a failed
        # probe rather than presenting an empty selector.
        logger.warning('CryptoPro reported no known paramsets for %s (got %s)',
                       key_alg, sorted(oids))
        return static
    _capi_paramset_cache[key_alg] = names
    return list(names)


def paramset_choices_for_ca(key_alg: str, ca_uuid: Optional[str] = None) -> list[str]:
    """Paramsets to offer for a key issued by a given CA: gost-engine's list for
    an openssl CA, the provider's own list for a CryptoPro-backed one."""
    if ca_uuid and read_ca_backend(str(ca_uuid))[0] == 'capilite':
        return capi_supported_paramsets(key_alg)
    return gost_paramset_choices(key_alg)


def generate_key(
    out_path: Path,
    key_alg: str,
    *,
    paramset: str = DEFAULT_GOST_PARAMSET,
) -> None:
    """Generate a private key at out_path with mode 0600.

    Supported families:
        gost2012_256, gost2012_512  (via gost-engine)
        rsa:2048, rsa:4096
        ec:P-256, ec:P-384
        ed25519

    ``paramset`` is only meaningful for the gost2012_* families; it is
    silently ignored for other algorithms. Invalid paramsets raise
    OwnCAError before shelling out so the user gets a clear message.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if key_alg.startswith('gost2012'):
        valid = gost_paramset_choices(key_alg)
        if paramset not in valid:
            raise OwnCAError(
                f'invalid paramset {paramset!r} for {key_alg}; '
                f'must be one of {", ".join(valid)}'
            )
        _run([
            'genpkey',
            '-algorithm', key_alg,
            '-pkeyopt', f'paramset:{paramset}',
            '-out', str(out_path),
        ])
    elif key_alg.startswith('rsa:'):
        bits = key_alg.split(':', 1)[1]
        _run([
            'genpkey',
            '-algorithm', 'RSA',
            '-pkeyopt', f'rsa_keygen_bits:{bits}',
            '-out', str(out_path),
        ])
    elif key_alg.startswith('ec:'):
        curve = key_alg.split(':', 1)[1]
        _run([
            'genpkey',
            '-algorithm', 'EC',
            '-pkeyopt', f'ec_paramgen_curve:{curve}',
            '-pkeyopt', 'ec_param_enc:named_curve',
            '-out', str(out_path),
        ])
    elif key_alg == 'ed25519':
        _run([
            'genpkey',
            '-algorithm', 'ED25519',
            '-out', str(out_path),
        ])
    else:
        raise OwnCAError(f'unsupported key algorithm: {key_alg}')
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# CA creation
# ---------------------------------------------------------------------------

@dataclass
class CASpec:
    name: str
    subject: str
    key_alg: str
    days: int
    pathlen: Optional[int] = None
    profile_vars: Optional[dict] = None
    # Distribution points to embed in the intermediate's own cert. For root
    # CAs these are ignored — `req -x509` doesn't read an extfile in our
    # current flow (root certs use the static [v3_ca] from openssl.cnf).
    crl_url: str = ''
    aia_url: str = ''
    ocsp_url: str = ''
    sia_url: str = ''
    freshest_crl_url: str = ''
    issuer_alt_names: list = field(default_factory=list)


def create_root_ca(ca_uuid: str, spec: CASpec) -> dict:
    """Create a self-signed root CA. Returns parsed metadata for the new cert."""
    ca_dir = _storage_root() / 'cas' / ca_uuid
    _ensure_dir(ca_dir)
    _init_ca_db(ca_dir)
    cnf = _write_openssl_cnf(
        ca_dir, spec.key_alg, pathlen=spec.pathlen, profile_vars=spec.profile_vars,
    )

    key_path = ca_dir / 'ca.key'
    cert_path = ca_dir / 'ca.crt'

    if _cryptopro_active_for(spec.key_alg):
        return _create_root_ca_capilite(ca_uuid, ca_dir, cert_path, spec)

    generate_key(key_path, spec.key_alg)
    _run([
        'req', '-x509', '-new',
        '-config', str(cnf),
        '-key', str(key_path),
        '-out', str(cert_path),
        '-days', str(spec.days),
        '-subj', spec.subject,
        '-extensions', 'v3_ca',
        *_md_args(spec.key_alg),
    ])
    _write_backend(ca_dir, 'openssl')
    return parse_cert(cert_path)


def _create_root_ca_capilite(ca_uuid: str, ca_dir: Path, cert_path: Path,
                             spec: CASpec) -> dict:
    """Create a self-signed GOST root CA on the CryptoPro backend: the key is
    generated inside a CryptoPro container and the root is self-signed via the
    ownca_capi shim (CryptSignAndEncodeCertificate). The container name is
    recorded on disk so the rest of the CA's lifecycle routes to CryptoPro too.

    The DER the shim emits is converted to PEM with openssl (reading a GOST cert
    needs no private key), so `ca.crt` stays PEM like every other CA."""
    container = _capi_container_for(ca_uuid)
    der_path = ca_dir / 'ca.der'
    x500 = _openssl_subj_to_x500(spec.subject)
    _store_x500_subject(ca_dir, x500)
    _store_x500_issuer(ca_dir, x500)   # self-signed: issuer == subject
    (ca_dir / 'key_alg').write_text(spec.key_alg + '\n')
    _write_ca_crl_days(ca_dir, spec.profile_vars)
    # 1. key in the container (consumes one gamma segment). CASpec carries no
    #    paramset — the CA form offers none — so request the module default
    #    explicitly, which is what generate_key() bakes into an openssl CA too.
    _run_capi(['genkey', '--container', container, '--alg', spec.key_alg,
               *_capi_paramset_args(spec.key_alg, DEFAULT_GOST_PARAMSET)])
    # 2. root CA extensions: BC critical CA:TRUE, KU critical keyCertSign+cRLSign,
    #    SKI. Encoded purely via CAPILite (no openssl).
    extspec = ca_dir / 'root_ext.txt'
    _write_extspec(
        extspec, is_ca=True, pathlen=spec.pathlen,
        ku=['keyCertSign', 'cRLSign'], ku_critical=True,
        eku=[], eku_critical=False, want_ski=True, want_aki=True,
    )
    # 3. self-signed root -> DER. Serial: 8 random bytes as even-length hex with
    # the top bit cleared (a positive ASN.1 INTEGER) and a low bit set (non-zero).
    _sn = bytearray(secrets.token_bytes(8))
    _sn[0] = (_sn[0] & 0x7F) | 0x40
    _sn[-1] |= 0x01
    serial_hex = _sn.hex()
    _run_capi([
        'selfsign',
        '--container', container,
        '--subject', _openssl_subj_to_x500(spec.subject),
        '--days', str(spec.days),
        '--serial', serial_hex,
        '--alg', spec.key_alg,
        '--extspec', str(extspec),
        '--out', str(der_path),
    ])
    # 3. DER -> canonical PEM. Base64 wrap in Python — NOT openssl: the CryptoPro
    # path must not invoke openssl for the GOST material (crypto stays in CAPILite;
    # this is pure encoding).
    cert_path.write_bytes(_der_file_to_pem(der_path, 'CERTIFICATE'))
    try:
        der_path.unlink()
    except OSError:
        pass
    _write_backend(ca_dir, f'capilite:{container}')
    return parse_cert(cert_path)


def _build_intermediate_extfile(workdir: Path, spec: 'CASpec') -> Optional[Path]:
    """Build an extfile that augments the v3_ca extensions with the parent's
    distribution points (CDP/AIA/OCSP/SIA/freshestCRL/issuerAltName), so the
    intermediate CA cert carries the chain-validation pointers expected by
    relying parties.

    Returns ``None`` if there is nothing to add — the parent's static
    ``[ v3_ca ]`` from openssl.cnf is then sufficient.
    """
    has_dp = (spec.crl_url or spec.aia_url or spec.ocsp_url or spec.sia_url
              or spec.freshest_crl_url or spec.issuer_alt_names)
    if not has_dp:
        return None

    pathlen_str = f', pathlen:{spec.pathlen}' if spec.pathlen is not None else ''
    lines = [
        '[ v3_intermediate_ca ]',
        f'basicConstraints       = critical, CA:TRUE{pathlen_str}',
        'keyUsage               = critical, keyCertSign, cRLSign',
        'subjectKeyIdentifier   = hash',
        'authorityKeyIdentifier = keyid:always',
    ]
    if spec.crl_url:
        lines.append(f'crlDistributionPoints = URI:{spec.crl_url}')
    aia_parts: list[str] = []
    if spec.aia_url:
        aia_parts.append(f'caIssuers;URI:{spec.aia_url}')
    if spec.ocsp_url:
        aia_parts.append(f'OCSP;URI:{spec.ocsp_url}')
    if aia_parts:
        lines.append('authorityInfoAccess = ' + ', '.join(aia_parts))
    if spec.sia_url:
        lines.append(f'subjectInfoAccess = caRepository;URI:{spec.sia_url}')
    if spec.freshest_crl_url:
        lines.append(f'freshestCRL = URI:{spec.freshest_crl_url}')
    if spec.issuer_alt_names:
        lines.append('issuerAltName = ' + ', '.join(spec.issuer_alt_names))

    extfile = workdir / 'intermediate_ext.cnf'
    extfile.write_text('\n'.join(lines) + '\n')
    return extfile


def _create_intermediate_ca_capilite(ca_uuid: str, parent_ca_uuid: str,
                                     spec: CASpec) -> dict:
    """Create an intermediate CA on the CryptoPro backend: child key in its own
    container, CA cert signed by the parent's container key via the shim."""
    ca_dir = _storage_root() / 'cas' / ca_uuid
    _ensure_dir(ca_dir)
    _init_ca_db(ca_dir)
    child_container = _capi_container_for(ca_uuid)
    parent_container = _capi_ca_container(parent_ca_uuid)
    der_path = ca_dir / 'ca.der'
    cert_path = ca_dir / 'ca.crt'
    x500 = _openssl_subj_to_x500(spec.subject)
    _store_x500_subject(ca_dir, x500)
    _store_x500_issuer(ca_dir, _read_x500_subject(parent_ca_uuid))
    (ca_dir / 'key_alg').write_text(spec.key_alg + '\n')
    _write_ca_crl_days(ca_dir, spec.profile_vars)

    # Refuse unencodable issuerAltName types BEFORE the key exists, so a
    # rejected CA leaves no orphan container behind.
    ian = _general_names_or_raise(spec.issuer_alt_names, 'issuerAltName')

    _run_capi(['genkey', '--container', child_container, '--alg', spec.key_alg,
               *_capi_paramset_args(spec.key_alg, DEFAULT_GOST_PARAMSET)])
    extspec = ca_dir / 'ca_ext.txt'
    _write_extspec(
        extspec, is_ca=True, pathlen=spec.pathlen,
        ku=['keyCertSign', 'cRLSign'], ku_critical=True,
        eku=[], eku_critical=False,
        cdp=spec.crl_url, aia_ca=spec.aia_url, aia_ocsp=spec.ocsp_url,
        sia_repo=spec.sia_url, freshest_crl=spec.freshest_crl_url,
        issuer_alt_names=ian,
        want_ski=True, want_aki=True,
    )
    _run_capi([
        'issue',
        '--container', parent_container,
        '--subject-container', child_container,
        '--subject', x500,
        '--issuer', _read_x500_subject(parent_ca_uuid),
        '--days', str(spec.days),
        '--serial', _capi_serial_hex(),
        '--alg', spec.key_alg,
        '--extspec', str(extspec),
        '--out', str(der_path),
    ])
    cert_path.write_bytes(_der_file_to_pem(der_path, 'CERTIFICATE'))
    try:
        der_path.unlink()
    except OSError:
        pass
    _write_backend(ca_dir, f'capilite:{child_container}')
    return parse_cert(cert_path)


def create_intermediate_ca(ca_uuid: str, parent_ca_uuid: str, spec: CASpec) -> dict:
    """Create an intermediate CA signed by parent_ca_uuid."""
    parent_dir = _storage_root() / 'cas' / parent_ca_uuid
    if not (parent_dir / 'ca.crt').exists():
        raise OwnCAError(f'parent CA {parent_ca_uuid} not found on disk')
    if read_ca_backend(parent_ca_uuid)[0] == 'capilite':
        return _create_intermediate_ca_capilite(ca_uuid, parent_ca_uuid, spec)
    parent_cnf = parent_dir / 'openssl.cnf'

    ca_dir = _storage_root() / 'cas' / ca_uuid
    _ensure_dir(ca_dir)
    _init_ca_db(ca_dir)
    child_cnf = _write_openssl_cnf(
        ca_dir, spec.key_alg, pathlen=spec.pathlen, profile_vars=spec.profile_vars,
    )

    key_path = ca_dir / 'ca.key'
    csr_path = ca_dir / 'ca.csr'
    cert_path = ca_dir / 'ca.crt'
    generate_key(key_path, spec.key_alg)

    _run([
        'req', '-new',
        '-config', str(child_cnf),
        '-key', str(key_path),
        '-out', str(csr_path),
        '-subj', spec.subject,
        *_md_args(spec.key_alg),
    ])
    extfile = _build_intermediate_extfile(ca_dir, spec)
    args = [
        'ca', '-batch', '-notext',
        '-config', str(parent_cnf),
        '-days', str(spec.days),
        '-in', str(csr_path),
        '-out', str(cert_path),
    ]
    if extfile is not None:
        args += ['-extfile', str(extfile), '-extensions', 'v3_intermediate_ca']
    else:
        args += ['-extensions', 'v3_ca']
    _run(args)
    return parse_cert(cert_path)


# ---------------------------------------------------------------------------
# CA import (bring an existing cert + private key under management)
# ---------------------------------------------------------------------------

def _normalize_cert_pem(data: bytes) -> bytes:
    """Validate an uploaded certificate and return it as canonical PEM.

    Accepts PEM or DER input; raises OwnCAError on anything openssl can't
    read as an X.509 certificate.
    """
    with tempfile.NamedTemporaryFile(suffix='.crt') as tf:
        tf.write(data)
        tf.flush()
        for inform in ('PEM', 'DER'):
            try:
                return _run(['x509', '-inform', inform, '-in', tf.name,
                             '-outform', 'PEM']).encode('utf-8')
            except OwnCAError:
                continue
    raise OwnCAError('could not parse the certificate — expected PEM or DER')


def _normalize_key_pem(data: bytes, passphrase: str = '') -> bytes:
    """Validate an uploaded private key and return it as canonical, unencrypted
    PEM. Accepts PEM or DER, encrypted or not; raises OwnCAError on failure
    (including a wrong/missing passphrase for an encrypted key)."""
    passin = ['-passin', f'pass:{passphrase}']
    with tempfile.NamedTemporaryFile(suffix='.key') as tf:
        tf.write(data)
        tf.flush()
        for inform in ('PEM', 'DER'):
            try:
                return _run(['pkey', '-inform', inform, '-in', tf.name,
                             *passin]).encode('utf-8')
            except OwnCAError:
                continue
    raise OwnCAError(
        'could not parse the private key — it may be in an unsupported format '
        'or the passphrase is wrong'
    )


def _cert_key_match(cert_path: Path, key_path: Path) -> bool:
    """Return True iff the private key's public half matches the certificate's
    public key (both rendered as SubjectPublicKeyInfo PEM)."""
    try:
        cert_pub = _run(['x509', '-in', str(cert_path), '-noout', '-pubkey'])
        key_pub = _run(['pkey', '-in', str(key_path), '-pubout'])
    except OwnCAError:
        return False
    return cert_pub.strip() == key_pub.strip() != ''


def _is_ca_cert(cert_path: Path) -> bool:
    """Return True iff the cert carries basicConstraints CA:TRUE. openssl prints
    the flag as ``CA:TRUE`` (a non-CA cert prints ``CA:FALSE``), so a plain
    substring test is both sufficient and robust across openssl versions that
    render the extension inline vs. on a following line."""
    return 'CA:TRUE' in cert_text(cert_path)


def key_alg_from_public_key_info(palg: str, text: str = '') -> tuple[str, str]:
    """Map an openssl ``Public Key Algorithm:`` label to ``(key_alg, family)``.

    ``key_alg`` is a KEY_ALG_CHOICES value (gost2012_256/512, rsa:<bits>,
    ec:P-256/P-384, ed25519) refined from the key size / curve lines of the
    surrounding ``openssl -text`` dump, or '' when the exact size or curve is
    not one this app offers (a P-521 key, say). ``family`` is one of
    gost/rsa/ec/ed25519, or '' when the label is unrecognised.

    The family is read from the label *only*, never from the rest of the dump:
    a signature algorithm belonging to another family — an RSA certificate
    signed by a GOST CA, for instance — must not leak into the answer. The
    family stays usable for compatibility checks even when ``key_alg`` is ''.
    """
    p = (palg or '').lower()
    low = (text or '').lower()

    # Without gost-engine, openssl prints the raw OID instead of a name — the
    # only form available on a CryptoPro-only build, where the engine is absent
    # by design.
    if '1.2.643.7.1.1.1.1' in p:
        return 'gost2012_256', 'gost'
    if '1.2.643.7.1.1.1.2' in p:
        return 'gost2012_512', 'gost'
    if '1.2.643.2.2.19' in p:        # GOST R 34.10-2001 — legacy, not offered
        return '', 'gost'
    if 'gost' in p:
        return ('gost2012_512' if '512' in p else 'gost2012_256'), 'gost'
    if 'ed25519' in p:
        return 'ed25519', 'ed25519'
    if 'ecpublickey' in p or p.startswith('ec'):
        if re.search(r'prime256v1|secp256r1|\bp-256\b', low):
            return 'ec:P-256', 'ec'
        if re.search(r'secp384r1|\bp-384\b', low):
            return 'ec:P-384', 'ec'
        return '', 'ec'
    if 'rsa' in p:
        bits = re.search(r'public-key:\s*\((\d+)\s*bit\)', low)
        return (f'rsa:{bits.group(1)}' if bits else 'rsa:2048'), 'rsa'
    return '', ''


def detect_cert_key_info(cert_path: Path) -> tuple[str, str]:
    """``(key_alg, family)`` for a certificate's own public key — see
    key_alg_from_public_key_info. The family survives an algorithm whose exact
    size or curve this app does not offer, so it is what compatibility checks
    should use."""
    text = cert_text(cert_path)
    m = re.search(r'public key algorithm:\s*(.+)', text.lower())
    return key_alg_from_public_key_info(m.group(1).strip() if m else '', text)


def detect_cert_key_alg(cert_path: Path) -> str:
    """Best-effort mapping of a certificate's public key to a KEY_ALG_CHOICES
    value (gost2012_256/512, rsa:<bits>, ec:P-256/P-384, ed25519). Returns ''
    when it can't be determined."""
    return detect_cert_key_info(cert_path)[0]


def pkcs12_extract(pfx_bytes: bytes, passphrase: str = '') -> tuple[bytes, bytes]:
    """Extract the certificate + private key from a PKCS#12 (.pfx/.p12) blob.

    Returns ``(cert_pem, key_pem)`` — the certificate matching the private key
    (openssl ``-clcerts``) and the decrypted private key (``-nodes``), both as
    raw PEM. Any additional CA certs bundled in the container are ignored; only
    the leaf/holder certificate (the one whose key we hold) is imported.

    Retries with the OpenSSL legacy provider so PFX files sealed with older
    ciphers (RC2-40 / 3DES — common exports from Windows) still import. Raises
    OwnCAError when the passphrase is wrong or the container is unreadable. The
    returned PEM is fed straight into ``import_ca`` (already unencrypted, so pass
    ``passphrase=''`` there), which performs the CA / key-match validation.
    """
    passin = f'pass:{passphrase}'

    def _extract(extra: list[str]) -> tuple[bytes, bytes]:
        with tempfile.NamedTemporaryFile(suffix='.p12') as tf:
            tf.write(pfx_bytes)
            tf.flush()
            cert = _run(['pkcs12', '-in', tf.name, '-clcerts', '-nokeys',
                         '-passin', passin, *extra])
            key = _run(['pkcs12', '-in', tf.name, '-nocerts', '-nodes',
                        '-passin', passin, *extra])
        return cert.encode('utf-8'), key.encode('utf-8')

    try:
        cert_pem, key_pem = _extract([])
    except OwnCAError:
        try:
            cert_pem, key_pem = _extract(['-legacy'])
        except OwnCAError as e:
            raise OwnCAError(
                'could not read the PKCS#12 file — the passphrase may be wrong '
                'or the container uses an unsupported algorithm'
            ) from e

    if b'BEGIN CERTIFICATE' not in cert_pem:
        raise OwnCAError('the PKCS#12 file contains no certificate')
    if b'PRIVATE KEY' not in key_pem:
        raise OwnCAError('the PKCS#12 file contains no private key')
    return cert_pem, key_pem


def pkcs12_peek_key_alg(pfx_bytes: bytes, passphrase: str = '') -> str:
    """Best-effort: the key algorithm of the holder certificate inside a PFX,
    reading ONLY the certificate (``-clcerts -nokeys`` — no key material is
    ever extracted). Returns '' when openssl cannot read the container at all
    (e.g. an unknown bag PBE). Used to route a PFX import between the openssl
    and CryptoPro backends before anything touches the key."""
    passin = f'pass:{passphrase}'
    for extra in ([], ['-legacy']):
        try:
            with tempfile.NamedTemporaryFile(suffix='.p12') as tf:
                tf.write(pfx_bytes)
                tf.flush()
                cert = _run(['pkcs12', '-in', tf.name, '-clcerts', '-nokeys',
                             '-passin', passin, *extra])
        except OwnCAError:
            continue
        if 'BEGIN CERTIFICATE' not in cert:
            continue
        with tempfile.NamedTemporaryFile(suffix='.pem') as cf:
            cf.write(cert.encode('utf-8'))
            cf.flush()
            return detect_cert_key_alg(Path(cf.name)) or ''
    return ''


def import_ca(ca_uuid: str, cert_pem: bytes, key_pem: bytes,
              *, passphrase: str = '') -> dict:
    """Import an existing CA (certificate + private key) into OwnCA storage.

    Validates that the supplied material is a CA certificate whose public key
    matches the supplied private key, then lays out the on-disk CA directory
    (openssl.cnf, bookkeeping db, ca.crt, ca.key) exactly as create_root_ca /
    create_intermediate_ca would, so the imported CA can immediately sign certs
    and generate CRLs.

    Returns the parse_cert metadata plus ``key_alg`` (detected) and
    ``is_self_signed`` (subject == issuer). Raises OwnCAError on any validation
    failure; the caller is responsible for cleaning up storage on error.
    """
    cert_norm = _normalize_cert_pem(cert_pem)
    key_norm = _normalize_key_pem(key_pem, passphrase)

    ca_dir = _storage_root() / 'cas' / ca_uuid
    _ensure_dir(ca_dir)
    cert_path = ca_dir / 'ca.crt'
    key_path = ca_dir / 'ca.key'
    cert_path.write_bytes(cert_norm)
    _write_secret(key_path, key_norm)

    if not _cert_key_match(cert_path, key_path):
        raise OwnCAError('the private key does not match the certificate')
    if not _is_ca_cert(cert_path):
        raise OwnCAError(
            'the certificate is not a CA (basicConstraints CA:TRUE is missing) '
            'and cannot be used to sign certificates'
        )

    key_alg = detect_cert_key_alg(cert_path)
    if not key_alg:
        raise OwnCAError('could not determine the certificate key algorithm')
    # With CryptoPro enabled, GOST crypto must stay inside CAPILite: a PEM key
    # import would put the key on disk and run this CA on openssl, bypassing
    # the certified backend. Reject with a pointer to the PFX path (which
    # imports via PFXImportCertStore into a CryptoPro container).
    if _cryptopro_active_for(key_alg):
        raise OwnCAError(
            'CryptoPro CSP is enabled: import GOST CAs as a PKCS#12/PFX so '
            'the private key goes into a CryptoPro container. A PEM key '
            'import would run this CA on openssl, bypassing the certified '
            'backend.'
        )

    _init_ca_db(ca_dir)
    _write_openssl_cnf(ca_dir, key_alg)

    info = parse_cert(cert_path)
    info['key_alg'] = key_alg
    subject = info.get('subject', '')
    info['is_self_signed'] = bool(subject) and subject == info.get('issuer', '')
    return info


def import_ca_capilite(ca_uuid: str, pfx_bytes: bytes,
                       *, passphrase: str = '') -> dict:
    """Import an existing GOST CA from a PKCS#12/PFX onto the CryptoPro backend.

    The whole import runs through CAPILite (shim `importpfx`:
    PFXIsPFXBlob -> PFXVerifyPassword -> PFXImportCertStore) — the private key
    goes straight into a CryptoPro container and NEVER exists as a PEM on disk.
    The imported CA is registered as capilite-backed, so its whole lifecycle
    (issue / CRL / renew / p12) routes through CryptoPro, exactly like a CA
    created here. openssl is only used to read certificate metadata.

    Raises OwnCAError on a wrong passphrase, a keyless PFX, or a non-CA cert;
    the caller is responsible for cleaning up storage on error (the CryptoPro
    container created by a failed import is dropped by the shim's own error
    paths before it reports success)."""
    ca_dir = _storage_root() / 'cas' / ca_uuid
    _ensure_dir(ca_dir)
    cert_path = ca_dir / 'ca.crt'
    pfx_path = ca_dir / 'import.pfx'
    der_path = ca_dir / 'ca.der'
    pfx_path.write_bytes(pfx_bytes)
    try:
        out = _run_capi([
            'importpfx',
            '--pfx', str(pfx_path),
            '--password', passphrase or '',
            '--out', str(der_path),
        ])
        import json as _json
        try:
            meta = _json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError) as e:
            raise OwnCAError(f'unexpected importpfx output: {out!r}') from e
        container = meta.get('container', '')
        provtype = int(meta.get('provtype') or 0)
        subject_x500 = meta.get('subject', '')
        if not container:
            raise OwnCAError('importpfx reported no key container')
        cert_path.write_bytes(_der_file_to_pem(der_path, 'CERTIFICATE'))
    finally:
        for p in (pfx_path, der_path):
            try:
                p.unlink()
            except OSError:
                pass

    provtype_alg = 'gost2012_512' if provtype == 81 else 'gost2012_256'
    # PFXImportCertStore has already put the key in a container by now, and its
    # name (pfx-<guid>) cannot be derived from the CA UUID — so a rejection here
    # has to drop it directly. The caller only knows how to remove the storage
    # directory, which would leave the key behind, unreachable.
    try:
        if not _is_ca_cert(cert_path):
            raise OwnCAError(
                'the certificate is not a CA (basicConstraints CA:TRUE is '
                'missing) and cannot be used to sign certificates'
            )
        # provtype names the CryptoPro provider the key landed in, not what the
        # certificate holds. Taken alone it would record any non-GOST PFX as
        # gost2012_256 — a CA whose declared family is a lie, which then offers
        # GOST algorithms for an RSA key. Read the certificate and refuse
        # anything positively non-GOST; this path exists for GOST CAs only. An
        # empty family means openssl printed an OID it has no name for (no
        # gost-engine on a CryptoPro-only build) — that is the GOST case, and
        # provtype resolves 256 vs 512.
        cert_key_alg, cert_family = detect_cert_key_info(cert_path)
        if cert_family and cert_family != 'gost':
            raise OwnCAError(
                f'this PKCS#12 holds a {cert_family} key, not a GOST one — the '
                f'CryptoPro import path is for GOST CAs. Import it as a PEM '
                f'certificate + key pair, or as a PKCS#12 openssl can read.'
            )
    except OwnCAError:
        delete_capi_container(container, provtype_alg)
        raise
    key_alg = cert_key_alg or provtype_alg

    _store_x500_subject(ca_dir, subject_x500)
    (ca_dir / 'key_alg').write_text(key_alg + '\n')
    _write_backend(ca_dir, f'capilite:{container}')

    info = parse_cert(cert_path)
    info['key_alg'] = key_alg
    subject = info.get('subject', '')
    info['is_self_signed'] = bool(subject) and subject == info.get('issuer', '')
    return info


# ---------------------------------------------------------------------------
# end-entity certificate signing
# ---------------------------------------------------------------------------

@dataclass
class CertSpec:
    common_name: str
    subject: str
    key_alg: str
    days: int
    ext_lines: list       # rendered extension lines from CertProfile.to_extfile_lines()
    san_dns: list[str]
    san_ip: list[str]
    san_email: list[str] = field(default_factory=list)   # rfc822Name entries
    san_uri: list[str] = field(default_factory=list)     # uniformResourceIdentifier entries
    san_other: list[str] = field(default_factory=list)    # otherName entries (OID;TYPE:VALUE)
    crl_url: str = ''             # cdp injected into the cert (single-URL form)
    aia_url: str = ''             # caIssuers AIA injected into the cert
    ocsp_url: str = ''            # OCSP responder URL appended to AIA
    sia_url: str = ''             # caRepository SIA URL (RFC 5280 §4.2.2.2)
    freshest_crl_url: str = ''    # delta-CRL pointer (RFC 5280 §4.2.1.15)
    issuer_alt_names: list[str] = field(default_factory=list)  # one entry per item ("email:..", "URI:..", etc.)
    # GOST R 34.10-2012 paramset for server-side key generation. Ignored when
    # a caller supplies an external CSR (the paramset is then baked into the
    # subject public key of the CSR itself) and for non-GOST algorithms.
    paramset: str = DEFAULT_GOST_PARAMSET


def _build_extfile(workdir: Path, spec: CertSpec) -> Path:
    """Build a per-issue openssl extfile.cnf from the data-driven extension
    lines (rendered by CertProfile.to_extfile_lines) plus optional SAN and the
    CA-resolved distribution points (CDP, AIA, OCSP, SIA, freshestCRL,
    issuerAltName). Always creates an extfile — there are no hardcoded v3_*
    fallbacks.

    The profile's ``ext_lines`` may already contain section blocks for
    extensions that need their own [foo] sections (currently
    certificatePolicies). Those sections appear in the same list and are
    written verbatim — openssl resolves @section references regardless of
    order within the file.
    """
    lines = ['[ cert_ext ]']

    # Profile-rendered lines are written first. They may contain inline section
    # blocks (e.g. [polsect_1]) — openssl tolerates these mixed in.
    lines.extend(spec.ext_lines)

    has_san = spec.san_dns or spec.san_ip or spec.san_email or spec.san_uri or spec.san_other
    if has_san:
        lines.append('subjectAltName = @san_section')

    # CRL Distribution Points — single-URL form covers the common case.
    if spec.crl_url:
        lines.append(f'crlDistributionPoints = URI:{spec.crl_url}')

    # Authority Information Access: caIssuers + OCSP, both optional, joined.
    aia_parts: list[str] = []
    if spec.aia_url:
        aia_parts.append(f'caIssuers;URI:{spec.aia_url}')
    if spec.ocsp_url:
        aia_parts.append(f'OCSP;URI:{spec.ocsp_url}')
    if aia_parts:
        lines.append('authorityInfoAccess = ' + ', '.join(aia_parts))

    # Subject Information Access — caRepository (sub-CAs) / repository pointers.
    if spec.sia_url:
        lines.append(f'subjectInfoAccess = caRepository;URI:{spec.sia_url}')

    # freshestCRL — delta-CRL pointer.
    if spec.freshest_crl_url:
        lines.append(f'freshestCRL = URI:{spec.freshest_crl_url}')

    # issuerAltName — one entry per list item, e.g. "email:ca@example.org".
    if spec.issuer_alt_names:
        lines.append('issuerAltName = ' + ', '.join(spec.issuer_alt_names))

    if has_san:
        lines.append('')
        lines.append('[ san_section ]')
        for i, dns in enumerate(spec.san_dns, start=1):
            lines.append(f'DNS.{i} = {dns}')
        for i, ip in enumerate(spec.san_ip, start=1):
            lines.append(f'IP.{i} = {ip}')
        for i, email in enumerate(spec.san_email, start=1):
            lines.append(f'email.{i} = {email}')
        for i, uri in enumerate(spec.san_uri, start=1):
            lines.append(f'URI.{i} = {uri}')
        for i, other in enumerate(spec.san_other, start=1):
            lines.append(f'otherName.{i} = {other}')

    extfile = workdir / 'extfile.cnf'
    extfile.write_text('\n'.join(lines) + '\n')
    return extfile


def _capi_key_id_args(ca_uuid: str, prof: dict) -> dict:
    """`_write_extspec` key-identifier arguments derived from a profile.

    The profile decides whether SKI/AKI appear at all — the openssl backend
    simply omits the extension when the line is absent, and this backend must
    match rather than always emitting both. `issuer:always` additionally needs
    the CA certificate's own issuer + serial, which identify the CA's
    certificate (RFC 5280 §4.2.1.1)."""
    args = {'want_ski': prof['want_ski'], 'want_aki': prof['want_aki']}
    if prof['want_aki'] and prof.get('aki_issuer'):
        args['aki_issuer_dn'] = _read_x500_issuer(ca_uuid)
        args['aki_issuer_serial'] = _ca_cert_serial_hex(ca_uuid)
    return args


def _write_subject_csr_capilite(cert_dir: Path, container: str, subject_x500: str,
                                key_alg: str) -> None:
    """Write `csr.pem` for a container-held subject key via the shim's `gencsr`.

    Best-effort: the certificate is already (or about to be) issued from the
    container itself, so a shim that predates `gencsr` must not turn a
    successful issuance into a failure. Without the file the UI simply hides the
    CSR download, which is the pre-existing behaviour."""
    der_path = cert_dir / 'csr.der'
    try:
        _run_capi([
            'gencsr',
            '--container', container,
            '--subject', subject_x500,
            '--alg', key_alg,
            '--out', str(der_path),
        ])
        (cert_dir / 'csr.pem').write_bytes(
            _der_file_to_pem(der_path, 'CERTIFICATE REQUEST'))
    except OwnCAError as e:
        logger.warning('gencsr failed for container %s: %s', container, e)
    finally:
        try:
            der_path.unlink()
        except OSError:
            pass


def _issue_certificate_capilite(ca_uuid: str, cert_uuid: str, spec: CertSpec,
                                *, csr_pem: Optional[bytes] = None) -> dict:
    """Issue an end-entity certificate on the CryptoPro backend. With server-side
    keygen the subject key is generated in its own CryptoPro container; with an
    external CSR the public key is taken from the (signature-verified) PKCS#10.
    Either way the cert is signed with the CA container key via the ownca_capi
    shim, all extensions encoded in CAPILite."""
    _reject_unsupported_spec_capilite(spec)
    ca_dir = _storage_root() / 'cas' / ca_uuid
    ca_container = _capi_ca_container(ca_uuid)
    ca_alg = _capi_alg_for(ca_uuid)
    cert_dir = _storage_root() / 'certs' / cert_uuid
    _ensure_dir(cert_dir)
    der_path = cert_dir / 'cert.der'
    cert_path = cert_dir / 'cert.pem'

    # extspec from the profile's rendered lines + structured SAN/CDP/AIA
    prof = _parse_profile_ext_lines(spec.ext_lines)
    extspec = cert_dir / 'ext.txt'
    _write_extspec(
        extspec, is_ca=prof['bc_ca'], pathlen=prof['bc_pathlen'],
        ku=prof['ku'], ku_critical=prof['ku_critical'],
        eku=prof['eku'], eku_critical=prof['eku_critical'],
        san_dns=spec.san_dns, san_ip=spec.san_ip, san_email=spec.san_email,
        san_uri=spec.san_uri,
        cdp=spec.crl_url, aia_ca=spec.aia_url, aia_ocsp=spec.ocsp_url,
        sia_repo=spec.sia_url, freshest_crl=spec.freshest_crl_url,
        issuer_alt_names=_split_general_names(spec.issuer_alt_names)[0],
        **_capi_key_id_args(ca_uuid, prof),
    )

    if csr_pem:
        # External CSR: keep the PEM (downloads/renew), hand the DER to the
        # shim. The shim verifies the CSR self-signature and takes the subject
        # public key + DN from the request itself.
        csr_path = cert_dir / 'csr.pem'
        csr_path.write_bytes(csr_pem)
        csr_der_path = cert_dir / 'csr.der'
        der = _pem_to_der(csr_pem)
        if not der:
            # not PEM-armored — assume the caller handed us DER already
            der = csr_pem
        csr_der_path.write_bytes(der)
        _run_capi([
            'issuecsr',
            '--container', ca_container,
            '--csr', str(csr_der_path),
            '--issuer', _read_x500_subject(ca_uuid),
            '--days', str(spec.days),
            '--serial', _capi_serial_hex(),
            '--alg', ca_alg,
            '--extspec', str(extspec),
            '--out', str(der_path),
        ])
        has_key = False
    else:
        # subject key in its own container, with the requested GOST paramset
        subj_container = _capi_cert_container_for(cert_uuid)
        _run_capi(['genkey', '--container', subj_container, '--alg', spec.key_alg,
                   *_capi_paramset_args(spec.key_alg, spec.paramset)])
        # A PKCS#10 for the freshly generated key. The signing call below takes
        # the public key straight from the container, so this request is not
        # needed to issue — it exists so a server-generated cert leaves the same
        # csr.pem the openssl backend writes (download + renew + the storage
        # layout this module documents).
        _write_subject_csr_capilite(cert_dir, subj_container,
                                    _openssl_subj_to_x500(spec.subject),
                                    spec.key_alg)
        _run_capi([
            'issue',
            '--container', ca_container,
            '--subject-container', subj_container,
            '--subject', _openssl_subj_to_x500(spec.subject),
            '--issuer', _read_x500_subject(ca_uuid),
            '--days', str(spec.days),
            '--serial', _capi_serial_hex(),
            '--alg', ca_alg,
            '--subject-alg', spec.key_alg,
            '--extspec', str(extspec),
            '--out', str(der_path),
        ])
        # record the subject key container so PKCS#12 export can find the key,
        # and the exact X.500 subject so renew can re-issue byte-stably
        (cert_dir / 'container').write_text(subj_container + '\n')
        (cert_dir / 'subject_x500').write_text(
            _openssl_subj_to_x500(spec.subject) + '\n')
        (cert_dir / 'key_alg').write_text(spec.key_alg + '\n')
        has_key = True

    cert_path.write_bytes(_der_file_to_pem(der_path, 'CERTIFICATE'))
    try:
        der_path.unlink()
    except OSError:
        pass
    info = parse_cert(cert_path)
    info['has_private_key'] = has_key
    return info


def issue_certificate(
    ca_uuid: str,
    cert_uuid: str,
    spec: CertSpec,
    *,
    csr_pem: Optional[bytes] = None,
) -> dict:
    """Issue a certificate against the given CA.

    If `csr_pem` is provided, it is used as the CSR. Otherwise, a fresh keypair
    and CSR are generated server-side. Returns parsed cert metadata.
    """
    ca_dir = _storage_root() / 'cas' / ca_uuid
    if not (ca_dir / 'ca.crt').exists():
        raise OwnCAError(f'CA {ca_uuid} not found on disk')
    if read_ca_backend(ca_uuid)[0] == 'capilite':
        return _issue_certificate_capilite(ca_uuid, cert_uuid, spec, csr_pem=csr_pem)
    ca_cnf = ca_dir / 'openssl.cnf'

    cert_dir = _storage_root() / 'certs' / cert_uuid
    _ensure_dir(cert_dir)

    csr_path = cert_dir / 'csr.pem'
    key_path = cert_dir / 'key.pem'
    cert_path = cert_dir / 'cert.pem'

    if csr_pem:
        csr_path.write_bytes(csr_pem)
        has_key = False
    else:
        generate_key(key_path, spec.key_alg, paramset=spec.paramset)
        _run([
            'req', '-new',
            '-config', str(ca_cnf),
            '-key', str(key_path),
            '-out', str(csr_path),
            '-subj', spec.subject,
            *_md_args(spec.key_alg),
        ])
        has_key = True

    extfile = _build_extfile(cert_dir, spec)

    args = [
        'ca', '-batch', '-notext',
        '-config', str(ca_cnf),
        '-days', str(spec.days),
        '-in', str(csr_path),
        '-out', str(cert_path),
        '-extfile', str(extfile),
        '-extensions', 'cert_ext',
    ]
    _run(args)

    info = parse_cert(cert_path)
    info['has_private_key'] = has_key
    return info


def _renew_certificate_capilite(ca_uuid: str, old_cert_uuid: str,
                                new_cert_uuid: str, spec: CertSpec) -> dict:
    """Renew on the CryptoPro backend. Server-keygen certs re-issue from the
    SAME subject container (same key, new serial/validity); external-CSR certs
    re-issue from the stored CSR via `issuecsr`. Extensions come from the new
    spec so they can drift between renewals (parity with the openssl path)."""
    _reject_unsupported_spec_capilite(spec)
    old_dir = _storage_root() / 'certs' / old_cert_uuid
    new_dir = _storage_root() / 'certs' / new_cert_uuid
    _ensure_dir(new_dir)
    ca_container = _capi_ca_container(ca_uuid)
    ca_alg = _capi_alg_for(ca_uuid)
    der_path = new_dir / 'cert.der'
    cert_path = new_dir / 'cert.pem'

    prof = _parse_profile_ext_lines(spec.ext_lines)
    extspec = new_dir / 'ext.txt'
    _write_extspec(
        extspec, is_ca=prof['bc_ca'], pathlen=prof['bc_pathlen'],
        ku=prof['ku'], ku_critical=prof['ku_critical'],
        eku=prof['eku'], eku_critical=prof['eku_critical'],
        san_dns=spec.san_dns, san_ip=spec.san_ip, san_email=spec.san_email,
        san_uri=spec.san_uri,
        cdp=spec.crl_url, aia_ca=spec.aia_url, aia_ocsp=spec.ocsp_url,
        sia_repo=spec.sia_url, freshest_crl=spec.freshest_crl_url,
        issuer_alt_names=_split_general_names(spec.issuer_alt_names)[0],
        **_capi_key_id_args(ca_uuid, prof),
    )

    container_marker = old_dir / 'container'
    old_csr = old_dir / 'csr.pem'
    if container_marker.exists():
        # server-generated key: re-issue from the same container
        subj_container = container_marker.read_text().strip()
        subj_alg_f = old_dir / 'key_alg'
        subj_alg = subj_alg_f.read_text().strip() if subj_alg_f.exists() else ca_alg
        subj_x500_f = old_dir / 'subject_x500'
        if subj_x500_f.exists():
            subject = subj_x500_f.read_text().strip()
        else:
            subject = _openssl_subj_to_x500(
                parse_cert(old_dir / 'cert.pem').get('subject', ''))
        _run_capi([
            'issue',
            '--container', ca_container,
            '--subject-container', subj_container,
            '--subject', subject,
            '--issuer', _read_x500_subject(ca_uuid),
            '--days', str(spec.days),
            '--serial', _capi_serial_hex(),
            '--alg', ca_alg,
            '--subject-alg', subj_alg,
            '--extspec', str(extspec),
            '--out', str(der_path),
        ])
        # the renewed cert shares the old cert's container/key
        (new_dir / 'container').write_text(subj_container + '\n')
        (new_dir / 'subject_x500').write_text(subject + '\n')
        (new_dir / 'key_alg').write_text(subj_alg + '\n')
        # Carry the request forward like the openssl path does, so the renewal
        # offers the same downloads as the certificate it replaces.
        if old_csr.exists():
            (new_dir / 'csr.pem').write_bytes(old_csr.read_bytes())
        has_key = True
    elif old_csr.exists():
        # external CSR: re-issue from the stored request
        csr_pem = old_csr.read_bytes()
        (new_dir / 'csr.pem').write_bytes(csr_pem)
        csr_der_path = new_dir / 'csr.der'
        der = _pem_to_der(csr_pem) or csr_pem
        csr_der_path.write_bytes(der)
        _run_capi([
            'issuecsr',
            '--container', ca_container,
            '--csr', str(csr_der_path),
            '--issuer', _read_x500_subject(ca_uuid),
            '--days', str(spec.days),
            '--serial', _capi_serial_hex(),
            '--alg', ca_alg,
            '--extspec', str(extspec),
            '--out', str(der_path),
        ])
        has_key = False
    else:
        raise OwnCAError(
            f'cert {old_cert_uuid} has neither a key container nor a CSR on '
            'disk — cannot renew')

    cert_path.write_bytes(_der_file_to_pem(der_path, 'CERTIFICATE'))
    try:
        der_path.unlink()
    except OSError:
        pass
    info = parse_cert(cert_path)
    info['has_private_key'] = has_key
    return info


def renew_certificate(
    ca_uuid: str,
    old_cert_uuid: str,
    new_cert_uuid: str,
    spec: CertSpec,
) -> dict:
    """Re-sign an existing CSR (and reuse its private key, if available) under
    a new certificate UUID with new validity. The original cert is left
    untouched on disk; callers should mark its DB row as superseded if they
    want a clean audit trail.

    The CSR text from the old cert directory is reused as-is — its embedded
    public key and Subject DN are preserved. Profile/SAN/CRL/AIA come from
    the new ``spec`` so they can drift between renewals.
    """
    ca_dir = _storage_root() / 'cas' / ca_uuid
    if not (ca_dir / 'ca.crt').exists():
        raise OwnCAError(f'CA {ca_uuid} not found on disk')
    if read_ca_backend(ca_uuid)[0] == 'capilite':
        return _renew_certificate_capilite(ca_uuid, old_cert_uuid,
                                           new_cert_uuid, spec)
    ca_cnf = ca_dir / 'openssl.cnf'

    old_dir = _storage_root() / 'certs' / old_cert_uuid
    old_csr = old_dir / 'csr.pem'
    old_key = old_dir / 'key.pem'
    if not old_csr.exists():
        raise OwnCAError(f'cert {old_cert_uuid} has no CSR on disk — cannot renew')

    new_dir = _storage_root() / 'certs' / new_cert_uuid
    _ensure_dir(new_dir)

    # Reuse the existing CSR (and key if present) by copying.
    new_csr = new_dir / 'csr.pem'
    new_csr.write_bytes(old_csr.read_bytes())

    has_key = False
    if old_key.exists():
        new_key = new_dir / 'key.pem'
        new_key.write_bytes(old_key.read_bytes())
        try:
            os.chmod(new_key, 0o600)
        except OSError:
            pass
        has_key = True

    new_cert = new_dir / 'cert.pem'
    extfile = _build_extfile(new_dir, spec)

    args = [
        'ca', '-batch', '-notext',
        '-config', str(ca_cnf),
        '-days', str(spec.days),
        '-in', str(new_csr),
        '-out', str(new_cert),
        '-extfile', str(extfile),
        '-extensions', 'cert_ext',
    ]
    _run(args)

    info = parse_cert(new_cert)
    info['has_private_key'] = has_key
    return info


GOST_PKCS12_CIPHERS = ('kuznyechik-ctr-acpkm', 'magma-ctr-acpkm')
GOST_PKCS12_MAC_ALG = 'md_gost12_512'


def _pem_to_der(pem: bytes) -> bytes:
    """Strip PEM armor and base64-decode to DER (no openssl)."""
    import base64
    body = []
    keep = False
    for line in pem.decode('ascii', 'replace').splitlines():
        if line.startswith('-----BEGIN'):
            keep = True
            continue
        if line.startswith('-----END'):
            break
        if keep:
            body.append(line.strip())
    return base64.b64decode(''.join(body))


def _pkcs12_export_capilite(cert_uuid: str, cert_dir: Path, cert_path: Path,
                            container: str, password: str,
                            chain_paths: Optional[list] = None) -> bytes:
    """Export a CryptoPro-issued cert + its container key to a PFX via the shim
    (PFXExportCertStoreEx). CA-chain certs ride along key-less (`--chain`).
    Uses CryptoPro's native PBE — NOT the TK-26 wire format the openssl path
    produces (a documented CryptoPro-backend limitation)."""
    der = _pem_to_der(cert_path.read_bytes())
    der_path = cert_dir / 'cert_for_pfx.der'
    der_path.write_bytes(der)
    pfx_path = cert_dir / 'export.pfx'
    alg = detect_cert_key_alg(cert_path) or 'gost2012_256'
    chain_der_paths: list[Path] = []
    try:
        args = [
            'exportpfx',
            '--container', container,
            '--cert', str(der_path),
            '--password', password or '',
            '--alg', alg,
        ]
        for i, p in enumerate(chain_paths or []):
            p = Path(p)
            if not p.exists():
                continue
            cp = cert_dir / f'chain_{i}.der'
            cp.write_bytes(_pem_to_der(p.read_bytes()))
            chain_der_paths.append(cp)
            args += ['--chain', str(cp)]
        args += ['--out', str(pfx_path)]
        _run_capi(args)
        return pfx_path.read_bytes()
    finally:
        for p in (der_path, pfx_path, *chain_der_paths):
            try:
                p.unlink()
            except OSError:
                pass


def pkcs12_export(
    cert_uuid: str,
    chain_paths: list[Path],
    password: str,
    *,
    friendly_name: str = '',
    gostkeybag: bool = False,
    keybag_cipher: str = 'kuznyechik-ctr-acpkm',
    certbag_cipher: str = 'kuznyechik-ctr-acpkm',
) -> bytes:
    """Bundle a certificate + private key + CA chain into a PKCS#12 (.p12)
    blob protected by ``password``.

    ``chain_paths`` should list every CA cert from the immediate issuer up
    to the root, in that order; they will all be included as `-certfile`
    entries so the resulting .p12 contains the full chain.

    When ``gostkeybag=True`` the bundle is produced as a TK-26 (RFC 9337 +
    RFC 9548) PFX: the keybag and cert envelope are wrapped with PBES2 /
    PBKDF2-HMAC-Streebog over a CTR-ACPKM cipher, and the outer MAC uses
    HMAC-Streebog-512 with the RFC 9548 §3 KDF. ``keybag_cipher`` and
    ``certbag_cipher`` pick the CTR-ACPKM cipher per slot (one of
    ``GOST_PKCS12_CIPHERS``). The gost-engine that the dev_env image
    ships (gost-engine/engine master; RFC 9337/9548 support merged
    upstream in PR #527) teaches stock ``openssl pkcs12`` how to emit
    this wire format.
    """
    cert_dir = _storage_root() / 'certs' / cert_uuid
    cert_path = cert_dir / 'cert.pem'
    key_path = cert_dir / 'key.pem'
    container_marker = cert_dir / 'container'
    if not cert_path.exists():
        raise OwnCAError(f'cert {cert_uuid} not found on disk')
    # CryptoPro-issued cert: the private key is in a CryptoPro container, not a
    # PEM. Export via the shim (PFXExportCertStoreEx), not openssl.
    if container_marker.exists():
        if gostkeybag:
            raise OwnCAError(
                'This certificate is backed by CryptoPro CSP: the PKCS#12 is '
                'produced by CryptoPro with its native encryption, so the '
                'TK-26 (.gost.p12) format cannot be selected here. Use the '
                'standard PKCS#12 export.'
            )
        return _pkcs12_export_capilite(cert_uuid, cert_dir, cert_path,
                                       container_marker.read_text().strip(),
                                       password, chain_paths)
    if not key_path.exists():
        raise OwnCAError('PKCS#12 export requires a server-stored private key')

    if gostkeybag:
        if keybag_cipher not in GOST_PKCS12_CIPHERS:
            raise OwnCAError(f'unsupported keybag cipher: {keybag_cipher}')
        if certbag_cipher not in GOST_PKCS12_CIPHERS:
            raise OwnCAError(f'unsupported certbag cipher: {certbag_cipher}')

    chain_bytes_list: list[bytes] = []
    for p in chain_paths:
        if Path(p).exists():
            chain_bytes_list.append(Path(p).read_bytes())

    # openssl pkcs12 takes a single -certfile, so concat the chain into one tmp.
    chain_pem = cert_dir / 'chain.tmp.pem'
    chain_blob = b''
    for b in chain_bytes_list:
        chain_blob += b
        if not chain_blob.endswith(b'\n'):
            chain_blob += b'\n'
    chain_pem.write_bytes(chain_blob)

    out_path = cert_dir / 'bundle.tmp.p12'
    args = [
        'pkcs12', '-export',
        '-inkey', str(key_path),
        '-in', str(cert_path),
        '-out', str(out_path),
        '-passout', f'pass:{password}',
    ]
    if gostkeybag:
        args += [
            '-keypbe', keybag_cipher,
            '-certpbe', certbag_cipher,
            '-macalg', GOST_PKCS12_MAC_ALG,
        ]
    if chain_blob:
        args += ['-certfile', str(chain_pem)]
    if friendly_name:
        args += ['-name', friendly_name]
    try:
        _run(args)
        return out_path.read_bytes()
    finally:
        try:
            chain_pem.unlink()
        except OSError:
            pass
        try:
            out_path.unlink()
        except OSError:
            pass


# PKCS#12 bag-encryption + MAC suites offered when exporting a CA to .p12.
# 'standard' leaves openssl on its own defaults (AES-256-CBC bags + SHA-256
# MAC) — the interoperable, non-GOST choice. The GOST suites require the
# gost-engine bundled in the runtime image (auto-loaded via openssl.cnf):
#   kuznyechik — TK-26 modern (RFC 9337 / 9548): kuznyechik-ctr-acpkm bags,
#                md_gost12_512 MAC.
#   magma      — TK-26 modern, Magma cipher:     magma-ctr-acpkm-omac bags,
#                md_gost12_256 MAC.
#   gost89     — legacy GOST 28147-89 + GOST R 34.11-94, for old CryptoPro-era
#                software that predates TK-26.
CA_PKCS12_PBE_SUITES = {
    'standard':   None,
    'kuznyechik': ('kuznyechik-ctr-acpkm', 'kuznyechik-ctr-acpkm', 'md_gost12_512'),
    'magma':      ('magma-ctr-acpkm-omac', 'magma-ctr-acpkm-omac', 'md_gost12_256'),
    'gost89':     ('gost89', 'gost89', 'md_gost94'),
}


def _pkcs12_export_ca_capilite(ca_uuid: str, container: str, password: str,
                               chain_paths: Optional[list]) -> bytes:
    """Export a CryptoPro-backed CA's certificate + container key to a PFX via
    the shim (PFXExportCertStoreEx). Parent-chain certs ride along key-less
    (`--chain`). Uses CryptoPro's native PBE — the PFX suite selection does not
    apply on this backend."""
    ca_dir = _storage_root() / 'cas' / ca_uuid
    cert_path = ca_dir / 'ca.crt'
    der_path = ca_dir / 'ca_for_pfx.der'
    der_path.write_bytes(_pem_to_der(cert_path.read_bytes()))
    pfx_path = ca_dir / 'export.pfx'
    chain_der_paths: list[Path] = []
    try:
        args = [
            'exportpfx',
            '--container', container,
            '--cert', str(der_path),
            '--password', password or '',
            '--alg', _capi_alg_for(ca_uuid),
        ]
        for i, p in enumerate(chain_paths or []):
            p = Path(p)
            if not p.exists():
                continue
            cp = ca_dir / f'chain_{i}.der'
            cp.write_bytes(_pem_to_der(p.read_bytes()))
            chain_der_paths.append(cp)
            args += ['--chain', str(cp)]
        args += ['--out', str(pfx_path)]
        _run_capi(args)
        return pfx_path.read_bytes()
    finally:
        for p in (der_path, pfx_path, *chain_der_paths):
            try:
                p.unlink()
            except OSError:
                pass


def pkcs12_export_ca(
    ca_uuid: str,
    password: str,
    *,
    friendly_name: str = '',
    pbe: str = 'standard',
    chain_paths: Optional[list] = None,
) -> bytes:
    """Bundle a CA's own certificate + private key (and optionally its parent
    chain) into a PKCS#12 (.p12) blob protected by ``password``.

    ``pbe`` selects the bag-encryption + MAC suite from CA_PKCS12_PBE_SUITES:
    'standard' (openssl AES defaults — most interoperable) or a GOST suite
    'kuznyechik' / 'magma' (TK-26, RFC 9337 / 9548) / 'gost89' (legacy GOST
    28147-89 + R 34.11-94, for old software). GOST suites need the gost-engine
    in the runtime image. The CA private key is stored unencrypted (0600), so
    no input passphrase is needed to read it.

    On a CryptoPro-backed CA the key lives in a container and the PFX is built
    by PFXExportCertStoreEx with CryptoPro's native PBE — the suite selection
    does not apply there: 'standard' maps to the native PBE, the GOST suites
    are rejected (we never silently substitute a different wire format).
    """
    ca_dir = _storage_root() / 'cas' / ca_uuid
    cert_path = ca_dir / 'ca.crt'
    key_path = ca_dir / 'ca.key'
    if not cert_path.exists():
        raise OwnCAError(f'CA {ca_uuid} certificate not found on disk')
    if pbe not in CA_PKCS12_PBE_SUITES:
        raise OwnCAError(f'unknown PKCS#12 encryption suite: {pbe}')
    backend, container = read_ca_backend(ca_uuid)
    if backend == 'capilite':
        if pbe != 'standard':
            raise OwnCAError(
                'This CA is backed by CryptoPro CSP: the PKCS#12 is produced '
                'by CryptoPro with its native encryption, so the GOST PBE '
                'suites (TK-26 / GOST 28147-89) cannot be selected here. '
                'Choose the standard suite.'
            )
        return _pkcs12_export_ca_capilite(ca_uuid, container, password,
                                          chain_paths)
    if not key_path.exists():
        raise OwnCAError('PKCS#12 export requires the CA private key on disk')

    chain_bytes = b''
    for p in (chain_paths or []):
        if Path(p).exists():
            chain_bytes += Path(p).read_bytes()
            if not chain_bytes.endswith(b'\n'):
                chain_bytes += b'\n'

    chain_tmp = None
    out_tmp = tempfile.NamedTemporaryFile(suffix='.p12', delete=False)
    out_tmp.close()
    try:
        args = [
            'pkcs12', '-export',
            '-inkey', str(key_path),
            '-in', str(cert_path),
            '-out', out_tmp.name,
            '-passout', f'pass:{password}',
        ]
        suite = CA_PKCS12_PBE_SUITES[pbe]
        if suite:
            keypbe, certpbe, macalg = suite
            args += ['-keypbe', keypbe, '-certpbe', certpbe, '-macalg', macalg]
        if chain_bytes:
            chain_tmp = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
            chain_tmp.write(chain_bytes)
            chain_tmp.close()
            args += ['-certfile', chain_tmp.name]
        if friendly_name:
            args += ['-name', friendly_name]
        _run(args)
        return Path(out_tmp.name).read_bytes()
    finally:
        for t in (out_tmp.name, chain_tmp.name if chain_tmp else None):
            if not t:
                continue
            try:
                os.unlink(t)
            except OSError:
                pass


def pem_bundle_export(cert_uuid: str, chain_paths: list[Path]) -> bytes:
    """Concatenate cert + private key (if present) + CA chain into a single
    PEM bundle (the format OpenVPN, HAProxy, and many other tools accept)."""
    cert_dir = _storage_root() / 'certs' / cert_uuid
    cert_path = cert_dir / 'cert.pem'
    key_path = cert_dir / 'key.pem'
    if not cert_path.exists():
        raise OwnCAError(f'cert {cert_uuid} not found on disk')

    out = bytearray()
    out += cert_path.read_bytes()
    if not out.endswith(b'\n'):
        out += b'\n'
    if key_path.exists():
        out += key_path.read_bytes()
        if not out.endswith(b'\n'):
            out += b'\n'
    for p in chain_paths:
        if Path(p).exists():
            out += Path(p).read_bytes()
            if not out.endswith(b'\n'):
                out += b'\n'
    return bytes(out)


# ---------------------------------------------------------------------------
# revocation + CRL
# ---------------------------------------------------------------------------

# RFC 5280 §5.3.1 CRLReason values, keyed by the reason names the UI stores in
# Certificate.revocation_reason (REVOCATION_REASON_CHOICES). openssl takes the
# NAME on the `ca -revoke` command line and encodes the extension itself; the
# CryptoPro shim has no such table, so the code is resolved here and passed per
# revoked entry. Matching openssl's table means both backends emit the same
# reasonCode for the same revocation.
CRL_REASON_CODES = {
    'unspecified': 0,
    'keyCompromise': 1,
    'CACompromise': 2,
    'affiliationChanged': 3,
    'superseded': 4,
    'cessationOfOperation': 5,
    'certificateHold': 6,
    'removeFromCRL': 8,
    'privilegeWithdrawn': 9,
    'AACompromise': 10,
}


def crl_reason_code(reason: str) -> Optional[int]:
    """Map a revocation reason name to its RFC 5280 code, or None when no
    reason was recorded (blank / unknown) — the caller then omits the
    reasonCode extension entirely, as openssl does."""
    return CRL_REASON_CODES.get((reason or '').strip())


def revoke_certificate(ca_uuid: str, cert_uuid: str, reason: str = 'unspecified') -> None:
    if read_ca_backend(ca_uuid)[0] == 'capilite':
        # No openssl index to update — revocation state is the DB row; the CRL is
        # rebuilt from the DB's revoked set (see generate_crl(..., revoked=...)).
        return
    ca_dir = _storage_root() / 'cas' / ca_uuid
    cert_path = _storage_root() / 'certs' / cert_uuid / 'cert.pem'
    if not cert_path.exists():
        raise OwnCAError(f'cert {cert_uuid} not found on disk')
    ca_cnf = ca_dir / 'openssl.cnf'
    args = [
        'ca',
        '-config', str(ca_cnf),
        '-revoke', str(cert_path),
    ]
    if reason:
        args += ['-crl_reason', reason]
    _run(args)


def _generate_crl_capilite(ca_uuid: str, revoked: list,
                           days: int = DEFAULT_CRL_DAYS) -> Path:
    """Sign a CRL with the CA container key via the shim. ``revoked`` is a list
    of (serial_hex, unix_time[, reason]) tuples — ``reason`` being a
    REVOCATION_REASON_CHOICES name. The CRL number auto-increments on disk."""
    ca_dir = _storage_root() / 'cas' / str(ca_uuid)
    container = _capi_ca_container(ca_uuid)
    crl_path = ca_dir / 'crl.pem'
    der_path = ca_dir / 'crl.der'
    rev_file = ca_dir / 'revoked.txt'
    lines = []
    for entry in revoked:
        serial_hex, ts = entry[0], entry[1]
        reason = entry[2] if len(entry) > 2 else ''
        s = str(serial_hex).replace(':', '').replace(' ', '')
        if len(s) % 2:
            s = '0' + s
        line = f'{s},{int(ts)}'
        # Only emit a reasonCode when one was actually recorded: an absent third
        # field tells the shim to omit the extension, matching what openssl does
        # for a revocation with no reason (rather than asserting `unspecified`).
        code = crl_reason_code(reason)
        if code is not None:
            line += f',{code}'
        lines.append(line)
    rev_file.write_text('\n'.join(lines) + ('\n' if lines else ''))

    # monotonic CRL number
    numf = ca_dir / 'crlnumber_capi'
    try:
        num = int(numf.read_text().strip()) + 1
    except (OSError, ValueError):
        num = 1
    numf.write_text(str(num))
    num_hex = '{:x}'.format(num)
    if len(num_hex) % 2:
        num_hex = '0' + num_hex

    _run_capi([
        'gencrl',
        '--container', container,
        '--issuer', _read_x500_subject(ca_uuid),
        '--days', str(int(days)),
        '--crlnumber', num_hex,
        '--revoked', str(rev_file),
        '--alg', _capi_alg_for(ca_uuid),
        '--out', str(der_path),
    ])
    crl_path.write_bytes(_der_file_to_pem(der_path, 'X509 CRL'))
    try:
        der_path.unlink()
    except OSError:
        pass
    return crl_path


def generate_crl(ca_uuid: str, revoked: Optional[list] = None,
                 days: Optional[int] = None) -> Path:
    """Regenerate a CA's CRL. For openssl CAs the revoked set comes from the
    on-disk index.txt (``revoked`` is ignored). For CryptoPro CAs there is no
    index — the caller passes ``revoked`` as a list of
    (serial_hex, unix_time[, reason]) tuples gathered from the DB.

    ``days`` overrides the CRL validity. Left as None, each backend uses the
    CA's configured value: openssl reads ``default_crl_days`` from its per-CA
    openssl.cnf, CryptoPro reads the ``crl_days`` marker — both seeded from
    DEFAULT_CRL_DAYS, so the two backends agree.
    """
    if read_ca_backend(ca_uuid)[0] == 'capilite':
        return _generate_crl_capilite(ca_uuid, revoked or [],
                                      days=days or _ca_crl_days(ca_uuid))
    ca_dir = _storage_root() / 'cas' / ca_uuid
    ca_cnf = ca_dir / 'openssl.cnf'
    crl_path = ca_dir / 'crl.pem'
    args = [
        'ca', '-gencrl',
        '-config', str(ca_cnf),
        '-out', str(crl_path),
    ]
    if days:
        args += ['-crldays', str(int(days))]
    _run(args)
    return crl_path


def export_crl(ca_uuid: str, ca_name: str) -> Path:
    """Copy a CA's freshly generated CRL into the shared crls/ export dir.

    The published file is named ``<ca_name>.crl`` (e.g. ``rsa_root.crl``) so
    operators can serve every CA's CRL from one predictable directory. The
    name is sanitised to a safe filename to keep the copy inside crls/.
    """
    crl_path = _storage_root() / 'cas' / ca_uuid / 'crl.pem'
    if not crl_path.exists():
        raise OwnCAError(f'CRL not generated for {ca_uuid}')
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', ca_name).strip('._') or ca_uuid
    crls_dir = _storage_root() / 'crls'
    _ensure_dir(crls_dir)
    out_path = crls_dir / f'{safe}.crl'
    shutil.copyfile(crl_path, out_path)
    return out_path


def read_crl_number(ca_uuid: str) -> str:
    """The CA's current CRL number, read from whichever counter its backend
    actually advances.

    A CryptoPro CA has BOTH files on disk: `crlnumber` is created by
    `_init_ca_db` at CA creation and then never moves (nothing runs `openssl ca`
    for that CA), while `_generate_crl_capilite` increments `crlnumber_capi`.
    Reading `crlnumber` first would therefore report the initial 1000 forever —
    so the backend, not file order, decides which counter is authoritative.
    """
    ca_dir = _storage_root() / 'cas' / ca_uuid
    if read_ca_backend(ca_uuid)[0] == 'capilite':
        names = ('crlnumber_capi', 'crlnumber')
    else:
        names = ('crlnumber', 'crlnumber_capi')
    for name in names:
        f = ca_dir / name
        if f.exists():
            return f.read_text().strip()
    return ''


# ---------------------------------------------------------------------------
# x509 parsing
# ---------------------------------------------------------------------------

_DATE_RE = re.compile(r'(\w+)\s*:\s*(.+)')


def parse_cert(cert_path: Path) -> dict:
    """Return subject/issuer/serial/dates/fingerprint dict for the given PEM."""
    if not Path(cert_path).exists():
        raise OwnCAError(f'certificate not found: {cert_path}')
    out = _run([
        'x509', '-in', str(cert_path), '-noout',
        '-subject', '-issuer', '-serial',
        '-startdate', '-enddate',
        '-fingerprint', '-sha256',
    ])
    info: dict[str, str] = {}
    for line in out.splitlines():
        if '=' not in line:
            continue
        key, _, val = line.partition('=')
        info[key.strip().lower()] = val.strip()
    return {
        'subject': info.get('subject', ''),
        'issuer': info.get('issuer', ''),
        'serial_hex': info.get('serial', ''),
        'not_before': _parse_openssl_date(info.get('notbefore', '')),
        'not_after': _parse_openssl_date(info.get('notafter', '')),
        'fingerprint_sha256': info.get('sha256 fingerprint', '').replace(':', ''),
    }


def _parse_openssl_date(s: str) -> Optional[dt.datetime]:
    if not s:
        return None
    # openssl format: "Apr  5 12:34:56 2030 GMT"
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%b  %d %H:%M:%S %Y %Z'):
        try:
            return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def cert_text(cert_path: Path) -> str:
    """Return human-readable `openssl x509 -text` output for a cert."""
    try:
        return _run(['x509', '-in', str(cert_path), '-noout', '-text'])
    except OwnCAError as e:
        return f'(unable to read certificate: {e})'


# Mapping from openssl's long attribute names (produced by `-nameopt multiline`)
# to the form fields used by cert_issue.html. Short name fallbacks let us also
# consume `nameopt compat` output from older openssl builds.
_CSR_SUBJECT_KEYS = {
    'commonName':               'common_name',
    'CN':                       'common_name',
    'countryName':              'country',
    'C':                        'country',
    'stateOrProvinceName':      'state',
    'ST':                       'state',
    'localityName':             'locality',
    'L':                        'locality',
    'organizationName':         'organization',
    'O':                        'organization',
    'organizationalUnitName':   'unit',
    'OU':                       'unit',
}


_PARAMSET_OID_MAP = [
    # CryptoPro legacy OIDs (gost-engine labels for 2012 256-bit paramsets)
    ('cryptopro-a-paramset', 'A'),
    ('cryptopro-b-paramset', 'B'),
    ('cryptopro-c-paramset', 'C'),
    ('cryptopro-xcha-paramset', 'XA'),
    ('cryptopro-xchb-paramset', 'XB'),
    # TC26 OIDs (modern 2012 256/512 paramsets)
    ('tc26-gost-3410-2012-256-paramseta', 'A'),
    ('tc26-gost-3410-2012-256-paramsetb', 'B'),
    ('tc26-gost-3410-2012-256-paramsetc', 'C'),
    ('tc26-gost-3410-12-256-paramseta', 'A'),
    ('tc26-gost-3410-12-256-paramsetb', 'B'),
    ('tc26-gost-3410-12-256-paramsetc', 'C'),
    ('tc26-gost-3410-2012-512-paramseta', 'A'),
    ('tc26-gost-3410-2012-512-paramsetb', 'B'),
    ('tc26-gost-3410-2012-512-paramsetc', 'C'),
    ('tc26-gost-3410-12-512-paramseta', 'A'),
    ('tc26-gost-3410-12-512-paramsetb', 'B'),
    ('tc26-gost-3410-12-512-paramsetc', 'C'),
]


def _normalize_gost_paramset(raw: str) -> str:
    """Map OpenSSL's paramset label to short A/B/C/XA/XB form. Returns '' when
    the OID doesn't look like a known GOST paramset."""
    if not raw:
        return ''
    r = raw.lower()
    for needle, label in _PARAMSET_OID_MAP:
        if needle in r:
            return label
    return ''


def _capture_ext_body(lines: list[str], header_idx: int) -> str:
    """Given the index of an 'X509v3 <name>:' header line in an openssl -text
    dump, join and return every indented continuation line until the next
    extension header or a shallower-indented marker. Returns a single
    space-joined string."""
    header_indent = len(lines[header_idx]) - len(lines[header_idx].lstrip())
    collected: list[str] = []
    for raw in lines[header_idx + 1:]:
        if not raw.strip():
            continue
        ind = len(raw) - len(raw.lstrip())
        if ind <= header_indent:
            break
        stripped = raw.strip()
        # Sibling extension / next section marker at deeper indent too — stop.
        if stripped.startswith('X509v3 ') or stripped.startswith('Signature Algorithm') \
                or stripped.startswith('Attributes'):
            break
        collected.append(stripped)
    return ' '.join(collected)


def parse_csr(csr_pem: bytes) -> dict:
    """Parse a PEM-encoded CSR and return a dict describing its contents.

    Returned keys:
        common_name, country, state, locality, organization, unit : str
        san_dns, san_ip                                            : list[str]
        signature_algorithm                                        : str
        public_key_algorithm                                       : str
        key_alg                                                    : str   (KEY_ALG_CHOICES value, or '' if the exact size/curve is not offered)
        key_family                                                 : str   (gost/rsa/ec/ed25519 or '')
        paramset                                                   : str   (A/B/C/XA/XB or '')
        paramset_raw                                               : str   (the raw OID label as openssl printed it)
        requested_ku                                               : list[str]
        requested_eku                                              : list[str]
        raw_text                                                   : str   (full `openssl req -text -noout` output, for display)

    Unknown / absent attributes come back as empty strings or empty lists.
    Raises OwnCAError if the CSR cannot be parsed by openssl.
    """
    if not csr_pem:
        raise OwnCAError('CSR is empty')

    # Parse subject in stable line-per-attribute form to avoid ambiguity with
    # commas inside values.
    subject_out = _run(
        ['req', '-noout', '-subject', '-nameopt', 'multiline'],
        input_bytes=csr_pem,
    )

    out: dict = {field: '' for field in set(_CSR_SUBJECT_KEYS.values())}
    out.update({
        'san_dns': [],
        'san_ip': [],
        'signature_algorithm': '',
        'public_key_algorithm': '',
        'key_alg': '',
        'key_family': '',
        'paramset': '',
        'paramset_raw': '',
        'requested_ku': [],
        'requested_eku': [],
        'raw_text': '',
    })

    for raw in subject_out.splitlines():
        line = raw.strip()
        if '=' not in line or line.lower().startswith('subject'):
            continue
        key, _, val = line.partition('=')
        field = _CSR_SUBJECT_KEYS.get(key.strip())
        if not field:
            continue
        val = val.strip()
        if out[field]:
            out[field] = f'{out[field]}, {val}'
        else:
            out[field] = val

    # Full text dump for everything else (SAN, KU, EKU, sig alg, paramset).
    try:
        text_out = _run(['req', '-noout', '-text'], input_bytes=csr_pem)
    except OwnCAError:
        text_out = ''
    out['raw_text'] = text_out.strip()

    lines = text_out.splitlines()

    # Top-level single-line fields. "Signature Algorithm:" appears once in a
    # CSR dump at the bottom (right before "Signature Value:").
    for raw in lines:
        s = raw.strip()
        if not out['public_key_algorithm'] and s.startswith('Public Key Algorithm:'):
            out['public_key_algorithm'] = s.split(':', 1)[1].strip()
        elif not out['paramset_raw'] and s.startswith('Parameter set:'):
            out['paramset_raw'] = s.split(':', 1)[1].strip()
            out['paramset'] = _normalize_gost_paramset(out['paramset_raw'])
        elif s.startswith('Signature Algorithm:'):
            # Use the *last* occurrence — in `openssl req -text` the signature
            # algorithm line is unique, but other X.509 dumps repeat it. Safe
            # to always overwrite.
            out['signature_algorithm'] = s.split(':', 1)[1].strip()

    out['key_alg'], out['key_family'] = key_alg_from_public_key_info(
        out['public_key_algorithm'], text_out,
    )

    # Requested extensions: locate each header, grab the indented body.
    ext_handlers = {
        'X509v3 Subject Alternative Name': 'san',
        'X509v3 Key Usage': 'ku',
        'X509v3 Extended Key Usage': 'eku',
    }
    for i, raw in enumerate(lines):
        stripped = raw.strip().rstrip(':').strip()
        for marker, kind in ext_handlers.items():
            if stripped == marker or stripped.startswith(marker + ' '):
                body = _capture_ext_body(lines, i)
                if kind == 'san':
                    for item in body.split(','):
                        item = item.strip()
                        if item.startswith('DNS:'):
                            out['san_dns'].append(item[4:].strip())
                        elif item.startswith('IP Address:'):
                            out['san_ip'].append(item[len('IP Address:'):].strip())
                        elif item.startswith('IP:'):
                            out['san_ip'].append(item[3:].strip())
                elif kind == 'ku':
                    out['requested_ku'] = [x.strip() for x in body.split(',') if x.strip()]
                elif kind == 'eku':
                    out['requested_eku'] = [x.strip() for x in body.split(',') if x.strip()]
                break

    return out


# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------

def delete_capi_container(container: str, key_alg: str = '') -> bool:
    """Drop a CryptoPro key container. Returns True when one was deleted.

    Removing the storage directory is not enough for a CryptoPro-backed CA or
    cert: its private key lives in a CSP container under
    ``/var/opt/cprocsp/keys``, outside the storage volume entirely. Left behind
    it becomes unreachable key material — nothing names it any more once the
    marker file that did is gone.

    Never raises. This runs on cleanup paths, including rollback after a failed
    creation, where a second failure must not mask the first; and a missing shim
    or an already-absent container is not an error.
    """
    if not container:
        return False
    try:
        out = _run_capi(['delcontainer', '--container', container,
                         *(['--alg', key_alg] if key_alg else [])])
    except OwnCAError as e:
        logger.warning('could not delete CryptoPro container %s: %s', container, e)
        return False
    import json as _json
    try:
        deleted = bool(_json.loads(out.strip().splitlines()[-1]).get('deleted'))
    except (ValueError, IndexError):
        logger.warning('unexpected delcontainer output for %s: %r', container, out)
        return False
    if deleted:
        logger.info('deleted CryptoPro container %s', container)
    return deleted


def _capi_container_referenced(container: str) -> bool:
    """True when any CA or certificate left on disk still names this container.

    A renewed certificate deliberately shares the container of the certificate
    it replaces — same key, new validity — so deleting either one must not take
    the key with it while the other still needs it. Called after the directory
    being discarded is already gone, so only surviving references count.
    """
    if not container:
        return False
    root = _storage_root()
    for marker in (root / 'certs').glob('*/container'):
        try:
            if marker.read_text().strip() == container:
                return True
        except OSError:
            continue
    for marker in (root / 'cas').glob('*/backend'):
        try:
            val = marker.read_text().strip()
        except OSError:
            continue
        if val.startswith('capilite:') and val.split(':', 1)[1] == container:
            return True
    return False


def _read_marker(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ''


def _capi_rollback_container(deterministic_name: str) -> str:
    """The container to try when no marker names one.

    Creation writes its marker only after the container exists, so a failure in
    between — and every caller here is also the rollback path for one — leaves a
    container that nothing points at. The deterministic name is derived from the
    CA/cert UUID and can therefore only ever be that record's own. Returns ''
    unless CryptoPro is actually in use, so an openssl-only install never invokes
    the shim on a delete.
    """
    from . import cryptopro
    return deterministic_name if cryptopro.enabled() else ''


# Whether to take the CryptoPro key container down with the storage directory.
#
# The default is True because every caller except the two delete views is a
# rollback path: the CA or cert never came into existence, so its container is
# unreferenced garbage the moment the directory goes — and for an imported one,
# garbage that can no longer even be named. Deliberate deletion of a real record
# is the case that asks first, and passes drop_container=False when the operator
# does not tick the box.
def delete_ca_storage(ca_uuid: str, *, drop_container: bool = True) -> None:
    p = _storage_root() / 'cas' / ca_uuid
    # Read the markers first — removing the directory takes them with it.
    backend, container = read_ca_backend(ca_uuid)
    key_alg = ''
    if backend == 'capilite':
        key_alg = _read_marker(p / 'key_alg')
    else:
        container = _capi_rollback_container(_capi_container_for(ca_uuid))
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    if drop_container and not _capi_container_referenced(container):
        delete_capi_container(container, key_alg)


def cert_has_capi_container(cert_uuid: str) -> bool:
    """True when this certificate's private key lives in a CryptoPro container.
    Only server-side key generation on a CryptoPro-backed CA produces one — a
    cert issued from an external CSR has no key here at all."""
    return (_storage_root() / 'certs' / str(cert_uuid) / 'container').exists()


def delete_cert_storage(cert_uuid: str, *, drop_container: bool = True) -> None:
    p = _storage_root() / 'certs' / cert_uuid
    container = _read_marker(p / 'container')
    key_alg = ''
    if container:
        key_alg = _read_marker(p / 'key_alg')
    else:
        container = _capi_rollback_container(_capi_cert_container_for(cert_uuid))
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
    if drop_container and not _capi_container_referenced(container):
        delete_capi_container(container, key_alg)
