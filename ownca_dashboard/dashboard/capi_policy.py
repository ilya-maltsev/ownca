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
What `openssl ca` enforces on its own and the ownca_capi shim does not.

The CryptoPro backend signs through the shim, which encodes whatever it is
handed. Three things the openssl path gets from `openssl ca` therefore have to
be done here, before the shim runs:

- DN quoting for CertStrToNameA — unquoted, ``O=Acme, CN=Administrator`` is two
  RDNs, so a comma in a value added a CN to the signed subject;
- the CA's ``[ policy_default ]`` (optional / supplied / match, unlisted fields
  dropped, ``email_in_dn = no``) — without it a CSR on a CryptoPro CA signed its
  own DN as-is;
- a well-formed revoked index — the shim used to skip a line it could not parse,
  which drops a revoked certificate from the CRL.

Pure Python, no third-party dependency: subjects are read from the DER with the
small reader below (only the Name is needed).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .own_ca import OwnCAError

# ---------------------------------------------------------------------------
# DN quoting
# ---------------------------------------------------------------------------

_DN_BREAKS = ('\n', '\r', '\x00')


def x500_quote(value: str) -> str:
    """Quote one RDN value for CertStrToNameA (CERT_X500_NAME_STR). Inside
    double quotes ``,`` ``;`` ``+`` are literal; a quote is written twice."""
    return '"' + value.replace('"', '""') + '"'


def split_openssl_subj(subj: str) -> list[tuple[str, str]]:
    """``/C=RU/CN=x`` -> ``[('C', 'RU'), ('CN', 'x')]``. Refuses line breaks."""
    s = (subj or '').strip()
    if any(br in s for br in _DN_BREAKS):
        raise OwnCAError('refusing a subject DN that contains a line break or NUL')
    out = []
    for rdn in (p for p in s.split('/') if p):
        key, sep, value = rdn.partition('=')
        if not sep or not key.strip():
            raise OwnCAError(f'malformed subject component: {rdn!r}')
        out.append((key.strip(), value.strip()))
    return out


def openssl_subj_to_x500(subj: str) -> str:
    """``/C=RU/O=Org/CN=Name`` -> ``C="RU", O="Org", CN="Name"``. A DN already
    in comma form (read back from a certificate or reported by the shim) is
    CryptoPro's or openssl's own rendering and is returned unchanged."""
    s = (subj or '').strip()
    if any(br in s for br in _DN_BREAKS):
        raise OwnCAError('refusing a subject DN that contains a line break or NUL')
    if not s.startswith('/'):
        return s
    return ', '.join(f'{k}={x500_quote(v)}' for k, v in split_openssl_subj(s))


# ---------------------------------------------------------------------------
# minimal DER reader — just enough to get a Name out of a CSR or certificate
# ---------------------------------------------------------------------------

def _tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, content start, content end) of the element at ``pos``."""
    if pos + 2 > len(buf):
        raise ValueError('truncated DER')
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if not 1 <= n <= 4 or pos + n > len(buf):
            raise ValueError('bad DER length')
        length = int.from_bytes(buf[pos:pos + n], 'big')
        pos += n
    if pos + length > len(buf):
        raise ValueError('truncated DER')
    return tag, pos, pos + length


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, pos = [], start
    while pos < end:
        tag, s, e = _tlv(buf, pos)
        out.append((tag, s, e))
        pos = e
    return out


def _oid(raw: bytes) -> str:
    if not raw:
        raise ValueError('empty OID')
    first = min(raw[0] // 40, 2)
    parts = [first, raw[0] - first * 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return '.'.join(map(str, parts))


_STRING_CODECS = {12: 'utf-8', 19: 'latin-1', 20: 'latin-1', 22: 'latin-1',
                  26: 'latin-1', 30: 'utf-16-be', 28: 'utf-32-be'}


def _name_rdns(buf: bytes, start: int, end: int) -> tuple[list[tuple[str, str]], bool]:
    """(OID, value) pairs of a Name, and whether every RDN is single-valued."""
    rdns, single = [], True
    for _tag, s, e in _children(buf, start, end):          # SET OF
        attrs = _children(buf, s, e)
        single = single and len(attrs) == 1
        for _t, as_, ae in attrs:                           # SEQUENCE {oid, value}
            (ot, os_, oe), (vt, vs, ve) = _children(buf, as_, ae)[:2]
            if ot != 0x06:
                raise ValueError('attribute type is not an OID')
            rdns.append((_oid(buf[os_:oe]),
                         buf[vs:ve].decode(_STRING_CODECS.get(vt, 'latin-1'))))
    return rdns, single


def _der(data: bytes) -> bytes:
    """The same bytes own_ca hands the shim (`_pem_to_der(pem) or pem`): the
    first PEM block only. Decoding anything else would let the policy vet one
    request while the shim signs another."""
    from .own_ca import _pem_to_der
    return _pem_to_der(data) or data


def csr_rdns(csr: bytes) -> tuple[list[tuple[str, str]], bool]:
    """Subject of a PKCS#10 (PEM or DER): CertificationRequestInfo.subject."""
    try:
        buf = _der(csr)
        _t, s, e = _tlv(buf, 0)
        _t, s, e = _children(buf, s, e)[0]                  # CertificationRequestInfo
        _t, s, e = _children(buf, s, e)[1]                  # version, *subject*
        return _name_rdns(buf, s, e)
    except (ValueError, IndexError, UnicodeDecodeError) as e:
        raise OwnCAError(f'cannot parse the CSR subject: {e}') from e


def cert_rdns(cert_path: Path) -> list[tuple[str, str]]:
    """Subject of a certificate (PEM or DER) on disk."""
    try:
        buf = _der(Path(cert_path).read_bytes())
        _t, s, e = _tlv(buf, 0)
        _t, s, e = _children(buf, s, e)[0]                  # tbsCertificate
        fields = _children(buf, s, e)
        if fields[0][0] == 0xA0:                            # [0] version
            fields = fields[1:]
        _t, s, e = fields[4]            # serial, signature, issuer, validity, *subject*
        return _name_rdns(buf, s, e)[0]
    except (OSError, ValueError, IndexError, UnicodeDecodeError) as e:
        raise OwnCAError(f'cannot read the subject of {cert_path}: {e}') from e


# ---------------------------------------------------------------------------
# subject DN policy — the CA's [ policy_default ], as `openssl ca` applies it
# ---------------------------------------------------------------------------

# (policy variable, openssl long name, CertStrToName key, OID)
_POLICY_FIELDS = (
    ('policy_country_name', 'countryName', 'C', '2.5.4.6'),
    ('policy_state_or_province_name', 'stateOrProvinceName', 'ST', '2.5.4.8'),
    ('policy_locality_name', 'localityName', 'L', '2.5.4.7'),
    ('policy_organization_name', 'organizationName', 'O', '2.5.4.10'),
    ('policy_organizational_unit_name', 'organizationalUnitName', 'OU', '2.5.4.11'),
    ('policy_common_name', 'commonName', 'CN', '2.5.4.3'),
    ('policy_email_address', 'emailAddress', 'E', '1.2.840.113549.1.9.1'),
)
_EMAIL_OID = '1.2.840.113549.1.9.1'
# openssl -subj accepts the short name, the long name or the dotted OID.
_SUBJ_KEY_TO_OID = {}
for _var, _long, _short, _oid_s in _POLICY_FIELDS:
    _SUBJ_KEY_TO_OID.update({_long: _oid_s, _oid_s: _oid_s})
    if _short != 'E':                       # openssl has no 'E' short name
        _SUBJ_KEY_TO_OID[_short] = _oid_s
_OID_TO_KEY = {oid: short for _v, _l, short, oid in _POLICY_FIELDS}
DN_POLICY_FILE = 'dn_policy.json'


def _policy_from_vars(vars_: dict) -> dict:
    return {var: str(vars_.get(var, 'optional')) for var, *_ in _POLICY_FIELDS}


def write_ca_policy(ca_dir: Path, profile_vars: dict | None) -> None:
    """Record the CA's DN policy next to its other markers (the openssl path
    keeps it in openssl.cnf, which a CryptoPro CA never runs)."""
    from .own_ca import _DEFAULT_CNF_VARS
    vars_ = {**_DEFAULT_CNF_VARS, **(profile_vars or {})}
    (Path(ca_dir) / DN_POLICY_FILE).write_text(
        json.dumps(_policy_from_vars(vars_), indent=1) + '\n')


def _ca_policy(ca_dir: Path) -> dict:
    from .own_ca import _DEFAULT_CNF_VARS
    policy = _policy_from_vars(_DEFAULT_CNF_VARS)
    try:
        stored = json.loads((Path(ca_dir) / DN_POLICY_FILE).read_text())
        policy.update({k: str(v) for k, v in stored.items() if k in policy})
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as e:
        raise OwnCAError(f'unreadable {DN_POLICY_FILE} in {ca_dir}: {e}') from e
    return policy


def apply_dn_policy(ca_dir: Path, rdns: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """The subject `openssl ca` would sign, or OwnCAError in openssl's wording.
    ``rdns`` are (OID, value) pairs; ``ca_dir`` is the SIGNING CA's directory."""
    policy = _ca_policy(ca_dir)
    out: list[tuple[str, str]] = []
    ca_subject = None
    for var, long_name, _short, oid in _POLICY_FIELDS:
        mode = (policy.get(var) or 'optional').strip()
        present = [v for o, v in rdns if o == oid]
        if mode not in ('optional', 'supplied', 'match'):
            raise OwnCAError(f"{long_name}:invalid type in 'policy' configuration")
        if mode == 'supplied' and not present:
            raise OwnCAError(f'The {long_name} field needed to be supplied and was missing')
        if mode == 'match':
            if not present:
                raise OwnCAError(f'The mandatory {long_name} field was missing')
            if ca_subject is None:
                ca_subject = cert_rdns(Path(ca_dir) / 'ca.crt')
            ca_values = [v for o, v in ca_subject if o == oid]
            if not ca_values:
                raise OwnCAError(f'The {long_name} field does not exist in the CA '
                                 "certificate, the 'policy' is misconfigured")
            for v in present:
                if v not in ca_values:
                    raise OwnCAError(f'The {long_name} field is different between '
                                     f'CA certificate ({ca_values[0]}) and the request ({v})')
        out.extend((oid, v) for v in present)
    # email_in_dn = no: checked by the policy above, never written into the DN.
    out = [(o, v) for o, v in out if o != _EMAIL_OID]
    if not out:
        raise OwnCAError('After applying the CA policy the subject is empty')
    return out


def rdns_to_x500(rdns: list[tuple[str, str]]) -> str:
    return ', '.join(f'{_OID_TO_KEY[o]}={x500_quote(v)}' for o, v in rdns)


def policy_subject(ca_dir: Path, subj: str) -> str:
    """X.500 subject for an openssl-form DN (form issuance, intermediate CA)."""
    rdns = [(_SUBJ_KEY_TO_OID.get(k, k), v) for k, v in split_openssl_subj(subj)]
    return rdns_to_x500(apply_dn_policy(ca_dir, rdns))


def csr_policy_subject(ca_dir: Path, csr: bytes) -> str | None:
    """``--subject`` for an `issuecsr`, or None when the policy leaves the CSR's
    DN exactly as it was — then the shim keeps the CSR's encoding byte for byte."""
    rdns, single = csr_rdns(csr)
    built = apply_dn_policy(ca_dir, rdns)
    return None if single and built == rdns else rdns_to_x500(built)


def cert_policy_subject(ca_dir: Path, cert_path: Path, stored_x500: str) -> str:
    """Subject for re-issuing from a key container (renewal): the stored one
    when the policy keeps it — byte-stable — else the policy-built DN."""
    rdns = cert_rdns(cert_path)
    built = apply_dn_policy(ca_dir, rdns)
    return stored_x500 if built == rdns and stored_x500 else rdns_to_x500(built)


# ---------------------------------------------------------------------------
# revoked index: serial,unixtime[,reason]
# ---------------------------------------------------------------------------

REVOKED_LINE = re.compile(r'([0-9a-f]{2,128}),([1-9][0-9]{0,11})(?:,([0-9]|10))?')


def check_revoked_lines(lines: list[str]) -> None:
    """Refuse the CRL on any malformed entry — the shim's own rule, checked
    before it runs. A skipped line would silently un-revoke a certificate."""
    for n, line in enumerate(lines, 1):
        if not REVOKED_LINE.fullmatch(line):
            raise OwnCAError(f'revoked index entry {n} is malformed ({line!r}) '
                             '— CRL not signed')
