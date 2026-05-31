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
import os
import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from django.conf import settings


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


_DEFAULT_CNF_VARS = {
    'default_days': 365,
    'default_crl_days': 30,
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


def create_intermediate_ca(ca_uuid: str, parent_ca_uuid: str, spec: CASpec) -> dict:
    """Create an intermediate CA signed by parent_ca_uuid."""
    parent_dir = _storage_root() / 'cas' / parent_ca_uuid
    if not (parent_dir / 'ca.crt').exists():
        raise OwnCAError(f'parent CA {parent_ca_uuid} not found on disk')
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
    if not cert_path.exists():
        raise OwnCAError(f'cert {cert_uuid} not found on disk')
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

def revoke_certificate(ca_uuid: str, cert_uuid: str, reason: str = 'unspecified') -> None:
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


def generate_crl(ca_uuid: str) -> Path:
    ca_dir = _storage_root() / 'cas' / ca_uuid
    ca_cnf = ca_dir / 'openssl.cnf'
    crl_path = ca_dir / 'crl.pem'
    _run([
        'ca', '-gencrl',
        '-config', str(ca_cnf),
        '-out', str(crl_path),
    ])
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
    f = _storage_root() / 'cas' / ca_uuid / 'crlnumber'
    if not f.exists():
        return ''
    return f.read_text().strip()


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

def delete_ca_storage(ca_uuid: str) -> None:
    p = _storage_root() / 'cas' / ca_uuid
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)


def delete_cert_storage(cert_uuid: str) -> None:
    p = _storage_root() / 'certs' / cert_uuid
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
