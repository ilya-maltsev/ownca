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


from __future__ import annotations

import datetime as dt
import logging
import re

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.db.models import Count
from django.http import FileResponse, Http404, HttpResponse, HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _

from . import own_ca
from . import cryptopro
from .decorators import superuser_required
from .own_ca import CASpec, CertSpec, OwnCAError
from .models import (
    CertificateAuthority,
    Certificate,
    CertificateRequest,
    CertProfile,
    CustomOidDefinition,
    ProfileOidField,
    CrlExport,
    UserProfile,
    SystemSettings,
    CryptoProSettings,
    KEY_ALG_CHOICES,
    CA_TYPE_CHOICES,
    PLACEMENT_CHOICES,
    ASN1_TYPE_CHOICES,
    CERT_REQUEST_STATUS_CHOICES,
    REVOCATION_REASON_CHOICES,
    key_alg_family,
)


log = logging.getLogger('dashboard')


def _split_lines(value: str) -> list[str]:
    """Split a textarea string into a list of non-empty trimmed lines."""
    if not value:
        return []
    return [line.strip() for line in value.splitlines() if line.strip()]


def _resolved_distribution_points(ca, cert_profile=None) -> dict:
    """Return the effective DP/AIA/OCSP/SIA/freshestCRL/issuerAltName values
    for a given (CA, profile) pair.

    Per-profile overrides (when set) win over the CA-level values; missing
    fields fall back to empty string / empty list. Used by every issuance
    code path so the precedence rule lives in exactly one place.
    """
    def pick(field):
        if cert_profile is not None:
            own = (getattr(cert_profile, field, '') or '').strip()
            if own:
                return own
        return (getattr(ca, field, '') or '').strip()

    return {
        'crl_url': pick('crl_url'),
        'aia_url': pick('aia_url'),
        'ocsp_url': pick('ocsp_url'),
        'sia_url': pick('sia_url'),
        'freshest_crl_url': pick('freshest_crl_url'),
        'issuer_alt_names': _split_lines(ca.issuer_alt_names),
    }


def _operator_cas(request):
    """Return all CAs — single-superuser demo has full access."""
    return CertificateAuthority.objects.all()


def _key_family_allowed(alg: str, sys_settings) -> bool:
    """Return whether a key algorithm's family is permitted by the issuance
    mode toggles. Shared by every workflow that lets an operator pick a key
    algorithm (CA creation and custom certificate issuance) so the policy
    lives in exactly one place."""
    fam = key_alg_family(alg)
    if fam == 'gost' and not sys_settings.allow_gost_keys:
        return False
    if fam == 'rsa' and not sys_settings.allow_rsa_keys:
        return False
    if fam in ('ec', 'ed25519') and not sys_settings.allow_ecdsa_keys:
        return False
    return True


def _allowed_key_alg_choices(sys_settings):
    """KEY_ALG_CHOICES filtered to the families enabled in issuance settings."""
    return [(v, label) for v, label in KEY_ALG_CHOICES
            if _key_family_allowed(v, sys_settings)]


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next')
            if next_url and url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                return redirect(next_url)
            return redirect('dashboard')
        error = True
    return render(request, 'dashboard/login.html', {'error': error})


def logout_view(request):
    logout(request)
    return redirect('login')


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _split_san(raw: str) -> list[str]:
    if not raw:
        return []
    return [p.strip() for p in re.split(r'[\s,;]+', raw) if p.strip()]


def _parse_subject_dn(subject: str) -> dict:
    """Parse an OpenSSL ``/KEY=val/KEY=val`` subject string into a form-field dict."""
    result = {}
    mapping = {'CN': 'common_name', 'C': 'country', 'ST': 'state',
               'L': 'locality', 'O': 'organization', 'OU': 'unit'}
    for part in subject.split('/'):
        if '=' in part:
            key, val = part.split('=', 1)
            if key in mapping:
                result[mapping[key]] = val.strip()
    return result


def _build_subject(cn: str, request) -> str:
    """Compose an OpenSSL subject DN from form fields. CN is required."""
    parts = []
    for field, key in (('C', 'country'), ('ST', 'state'), ('L', 'locality'),
                       ('O', 'organization'), ('OU', 'unit')):
        v = (request.POST.get(key) or '').strip()
        if v:
            parts.append(f'/{field}={v}')
    parts.append(f'/CN={cn}')
    return ''.join(parts)


def _subject_from_csr_fields(fields: dict) -> str:
    """Compose an OpenSSL subject DN from `own_ca.parse_csr()` output. CN is required."""
    parts = []
    for field, key in (('C', 'country'), ('ST', 'state'), ('L', 'locality'),
                       ('O', 'organization'), ('OU', 'unit')):
        v = (fields.get(key) or '').strip()
        if v:
            parts.append(f'/{field}={v}')
    parts.append(f'/CN={fields.get("common_name", "")}')
    return ''.join(parts)


def _revoked_for_crl(ca: CertificateAuthority) -> list:
    """Revoked (serial_hex, unix_time, reason) tuples for a CA — used to rebuild
    a CryptoPro CA's CRL (which has no openssl index.txt). openssl CAs ignore it.

    ``reason`` is the stored REVOCATION_REASON_CHOICES name; own_ca turns it
    into an RFC 5280 reasonCode so a CryptoPro CRL carries the same reason the
    openssl backend would have written."""
    out = []
    for c in ca.certificates.filter(status='revoked').exclude(serial_hex=''):
        ts = int(c.revoked_at.timestamp()) if c.revoked_at else 0
        out.append((c.serial_hex, ts, c.revocation_reason or ''))
    return out


# Shown when an operator reaches a key-bearing export for a CryptoPro-backed
# certificate. Not a temporary gap: a CSP container key is non-exportable by
# design, which is the point of running on the certified backend.
_CAPILITE_NO_KEY_EXPORT_MSG = (
    'This certificate is backed by CryptoPro CSP: its private key lives inside '
    'a CSP container and cannot be written out as a PEM. Use the PKCS#12 export '
    'instead — CryptoPro builds the container itself.'
)


def _ca_chain_paths(ca: CertificateAuthority) -> list:
    """Walk an issuer chain from the immediate issuer up to the root and
    return a list of CA cert file paths suitable for bundle/p12 export."""
    paths = []
    current = ca
    seen = set()
    while current and current.uuid not in seen:
        seen.add(current.uuid)
        if current.cert_path.exists():
            paths.append(current.cert_path)
        current = current.parent
    return paths


def _refresh_cert_metadata(cert: Certificate) -> None:
    """Re-parse the on-disk cert and write metadata back to the model."""
    try:
        info = own_ca.parse_cert(cert.cert_path)
    except OwnCAError:
        return
    cert.subject = info.get('subject', cert.subject)
    cert.serial_hex = info.get('serial_hex', cert.serial_hex)
    cert.fingerprint_sha256 = info.get('fingerprint_sha256', cert.fingerprint_sha256)
    cert.not_before = info.get('not_before') or cert.not_before
    cert.not_after = info.get('not_after') or cert.not_after
    cert.save()


def _expire_passed_certs():
    """Mark certs as 'expired' if their not_after is in the past."""
    now = timezone.now()
    Certificate.objects.filter(status='active', not_after__lt=now).update(status='expired')


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------

@superuser_required
def dashboard_view(request):
    _expire_passed_certs()
    cas = _operator_cas(request)
    certs = Certificate.objects.filter(issuer_ca__in=cas)
    soon = timezone.now() + dt.timedelta(days=30)
    ctx = {
        'page': 'dashboard',
        'cas_total': cas.count(),
        'cas_root': cas.filter(ca_type='root').count(),
        'cas_intermediate': cas.filter(ca_type='intermediate').count(),
        'cas': cas,
        'certs_total': certs.count(),
        'certs_active': certs.filter(status='active').count(),
        'certs_revoked': certs.filter(status='revoked').count(),
        'certs_expired': certs.filter(status='expired').count(),
        'expiring': certs.filter(
            status='active', not_after__lte=soon, not_after__gte=timezone.now(),
        ).select_related('issuer_ca')[:10],
        'recent': certs.select_related('issuer_ca').order_by('-created_at')[:10],
        'pending_count': CertificateRequest.objects.filter(status='pending').count(),
    }

    return render(request, 'dashboard/dashboard.html', ctx)


# ---------------------------------------------------------------------------
# Certificate Authorities
# ---------------------------------------------------------------------------

@superuser_required
def cas_view(request):
    cas = list(CertificateAuthority.objects.select_related('parent').all())
    for c in cas:
        # 'openssl' | 'capilite' — shown as a badge next to the algorithm
        c.crypto_backend = own_ca.read_ca_backend(str(c.uuid))[0]
    sys_settings = SystemSettings.get_solo()
    # A parent signs its intermediate, so the create form narrows the algorithm
    # list to the parent's key family — tag each candidate with it.
    parents = list(CertificateAuthority.objects.filter(is_enabled=True))
    for p in parents:
        p.family = key_alg_family(p.key_alg)
    return render(request, 'dashboard/cas.html', {
        'page': 'cas',
        'cas': cas,
        'parents': parents,
        'key_alg_choices': [(v, label, key_alg_family(v)) for v, label
                            in _allowed_key_alg_choices(sys_settings)],
        'ca_type_choices': CA_TYPE_CHOICES,
    })


@superuser_required
def ca_create_view(request):
    if request.method != 'POST':
        return redirect('cas')

    name = (request.POST.get('name') or '').strip()
    cn = (request.POST.get('common_name') or name).strip()
    ca_type = request.POST.get('ca_type', 'root')
    key_alg = request.POST.get('key_alg', 'gost2012_256')
    days = max(1, int(request.POST.get('days') or 3650))
    parent_uuid = request.POST.get('parent') or ''
    pathlen_raw = (request.POST.get('pathlen') or '').strip()
    pathlen = int(pathlen_raw) if pathlen_raw.isdigit() else None
    crl_url = (request.POST.get('crl_url') or '').strip()
    aia_url = (request.POST.get('aia_url') or '').strip()
    if not name or not cn:
        messages.error(request, 'Name and Common Name are required')
        return redirect('cas')
    if CertificateAuthority.objects.filter(name=name).exists():
        messages.error(request, f'CA "{name}" already exists')
        return redirect('cas')
    if not _key_family_allowed(key_alg, SystemSettings.get_solo()):
        messages.error(request, f'Key algorithm "{key_alg}" is disabled by issuance mode settings.')
        return redirect('cas')

    ocsp_url = (request.POST.get('ocsp_url') or '').strip()
    sia_url = (request.POST.get('sia_url') or '').strip()
    freshest_crl_url = (request.POST.get('freshest_crl_url') or '').strip()
    issuer_alt_names = (request.POST.get('issuer_alt_names') or '').strip()

    subject = _build_subject(cn, request)

    parent = (
        CertificateAuthority.objects.filter(uuid=parent_uuid).first()
        if ca_type == 'intermediate' and parent_uuid else None
    )
    # A parent signs its intermediate's certificate, so the two must share a key
    # family: a GOST root must not end up over an RSA intermediate. The form
    # narrows the algorithm list to the selected parent's family, but the check
    # has to hold server-side too — the request can arrive without it.
    if parent is not None and key_alg_family(key_alg) != key_alg_family(parent.key_alg):
        messages.error(
            request,
            f'Key algorithm "{key_alg}" is not compatible with the parent CA '
            f'"{parent.name}" (parent uses "{parent.key_alg}"). A CA can only '
            f'sign certificates from the same key family.'
        )
        return redirect('cas')

    # When this is an intermediate, the *parent's* distribution points are what
    # belong inside the new intermediate's own certificate (so chain consumers
    # can fetch the parent's CRL/AIA). For root CAs DP fields default to empty.
    spec_dp = {}
    if parent is not None:
        spec_dp = {
            'crl_url': parent.crl_url or '',
            'aia_url': parent.aia_url or '',
            'ocsp_url': parent.ocsp_url or '',
            'sia_url': parent.sia_url or '',
            'freshest_crl_url': parent.freshest_crl_url or '',
            'issuer_alt_names': _split_lines(parent.issuer_alt_names),
        }
    spec = CASpec(
        name=name, subject=subject, key_alg=key_alg, days=days,
        pathlen=pathlen, **spec_dp,
    )

    ca = CertificateAuthority.objects.create(
        name=name,
        ca_type=ca_type,
        subject=subject,
        key_alg=key_alg,
        crl_url=crl_url,
        aia_url=aia_url,
        ocsp_url=ocsp_url,
        sia_url=sia_url,
        freshest_crl_url=freshest_crl_url,
        issuer_alt_names=issuer_alt_names,
        parent=parent,
    )
    try:
        if ca_type == 'intermediate':
            if not ca.parent:
                raise OwnCAError('intermediate CA requires a parent CA')
            info = own_ca.create_intermediate_ca(str(ca.uuid), str(ca.parent.uuid), spec)
        else:
            info = own_ca.create_root_ca(str(ca.uuid), spec)
    except OwnCAError as e:
        ca.delete()
        own_ca.delete_ca_storage(str(ca.uuid))
        messages.error(request, f'CA creation failed: {e}')
        return redirect('cas')

    ca.subject = info.get('subject', subject)
    ca.serial_hex = info.get('serial_hex', '')
    ca.fingerprint_sha256 = info.get('fingerprint_sha256', '')
    ca.not_before = info.get('not_before')
    ca.not_after = info.get('not_after')
    ca.save()
    # Auto-assign the freshly created CA to its creator so they can see it in
    # operational lists (_operator_cas honours the M2M for every role now —
    # without this hook an admin who just created a CA would get a 404 on its
    # detail page from every page that filters through _operator_cas).
    creator_profile = getattr(request.user, 'profile', None)
    if creator_profile is not None:
        creator_profile.assigned_cas.add(ca)
    messages.success(request, f'CA "{ca.name}" created')
    return redirect('ca_detail', ca_uuid=ca.uuid)


def _read_pem_upload(request, file_field: str, text_field: str) -> bytes:
    """Read PEM/DER material from a multipart file upload, falling back to a
    pasted textarea. Returns b'' when neither is provided."""
    upload = request.FILES.get(file_field)
    if upload:
        return upload.read()
    text = (request.POST.get(text_field) or '').strip()
    return text.encode('utf-8') if text else b''


@superuser_required
def ca_import_view(request):
    """Import an existing CA (certificate + private key) so OwnCA can sign
    certificates with it. Mirrors ca_create_view, but the key/cert come from
    the operator's upload instead of being freshly generated."""
    if request.method != 'POST':
        return redirect('cas')

    name = (request.POST.get('name') or '').strip()
    if not name:
        messages.error(request, 'Name is required')
        return redirect('cas')
    if CertificateAuthority.objects.filter(name=name).exists():
        messages.error(request, f'CA "{name}" already exists')
        return redirect('cas')

    passphrase = request.POST.get('key_passphrase') or ''

    # A PKCS#12 (.pfx/.p12) upload bundles the cert + key in one container; when
    # present it supersedes the separate cert/key fields. With CryptoPro enabled
    # a GOST PFX is imported via CAPILite (PFXImportCertStore — the key goes
    # straight into a CryptoPro container, never onto disk); otherwise the PEM
    # is extracted with openssl and fed into the classic import_ca path.
    pfx_upload = request.FILES.get('pfx_file')
    pfx_bytes = None
    use_capilite = False
    cert_pem = key_pem = b''
    if pfx_upload:
        pfx_bytes = pfx_upload.read()
        if cryptopro.enabled():
            # cert-only probe (no key material). '' = openssl can't read the
            # container at all — e.g. a CryptoPro-native PFX — try CAPILite.
            probe_alg = own_ca.pkcs12_peek_key_alg(pfx_bytes, passphrase)
            use_capilite = (probe_alg.startswith('gost2012') or probe_alg == '')
        if not use_capilite:
            try:
                cert_pem, key_pem = own_ca.pkcs12_extract(pfx_bytes, passphrase)
            except OwnCAError as e:
                messages.error(request, f'Import failed: {e}')
                return redirect('cas')
            passphrase = ''
    else:
        cert_pem = _read_pem_upload(request, 'cert_file', 'cert_pem')
        key_pem = _read_pem_upload(request, 'key_file', 'key_pem')
        if not cert_pem:
            messages.error(request, 'A CA certificate is required (upload a file, paste PEM, or upload a PKCS#12)')
            return redirect('cas')
        if not key_pem:
            messages.error(request, 'The CA private key is required (upload a file, paste PEM, or upload a PKCS#12)')
            return redirect('cas')
    parent_uuid = request.POST.get('parent') or ''

    import uuid as uuid_lib
    ca_uuid = uuid_lib.uuid4()
    try:
        if use_capilite:
            info = own_ca.import_ca_capilite(str(ca_uuid), pfx_bytes,
                                             passphrase=passphrase)
        else:
            info = own_ca.import_ca(str(ca_uuid), cert_pem, key_pem,
                                    passphrase=passphrase)
    except OwnCAError as e:
        own_ca.delete_ca_storage(str(ca_uuid))
        messages.error(request, f'Import failed: {e}')
        return redirect('cas')

    is_self_signed = info.get('is_self_signed')
    parent = None
    if not is_self_signed and parent_uuid:
        parent = CertificateAuthority.objects.filter(uuid=parent_uuid).first()
    ca_type = 'root' if is_self_signed else 'intermediate'

    key_alg = info.get('key_alg') or 'gost2012_256'
    if not _key_family_allowed(key_alg, SystemSettings.get_solo()):
        own_ca.delete_ca_storage(str(ca_uuid))
        messages.error(request, f'Key algorithm "{key_alg}" is disabled by issuance mode settings.')
        return redirect('cas')
    # The parent link is what chain building walks, so it has to name the CA that
    # really issued this certificate — which cannot be one from another key
    # family. Detected from the imported certificate, never from the form: the
    # operator picks only the parent, not the algorithm.
    if parent is not None and key_alg_family(key_alg) != key_alg_family(parent.key_alg):
        own_ca.delete_ca_storage(str(ca_uuid))
        messages.error(
            request,
            f'The imported CA uses "{key_alg}", which is not compatible with the '
            f'parent CA "{parent.name}" ("{parent.key_alg}") — a CA of one key '
            f'family cannot have issued a certificate of another. Leave Parent CA '
            f'empty if the real issuer is not managed here.'
        )
        return redirect('cas')

    try:
        ca = CertificateAuthority.objects.create(
            uuid=ca_uuid,
            name=name,
            ca_type=ca_type,
            subject=info.get('subject', ''),
            key_alg=key_alg,
            serial_hex=info.get('serial_hex', ''),
            fingerprint_sha256=info.get('fingerprint_sha256', ''),
            not_before=info.get('not_before'),
            not_after=info.get('not_after'),
            parent=parent,
        )
    except Exception:
        own_ca.delete_ca_storage(str(ca_uuid))
        raise

    creator_profile = getattr(request.user, 'profile', None)
    if creator_profile is not None:
        creator_profile.assigned_cas.add(ca)
    messages.success(request, f'CA "{ca.name}" imported ({ca.get_ca_type_display()})')
    return redirect('ca_detail', ca_uuid=ca.uuid)


@superuser_required
def ca_detail_view(request, ca_uuid):
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)

    # Edit distribution points (CRL / AIA / OCSP / SIA / freshestCRL / issuerAltName).
    # Surfaces values that previously could only be set at CA creation time.
    if request.method == 'POST' and request.POST.get('action') == 'set_distribution_points':
        ca.crl_url = (request.POST.get('crl_url') or '').strip()
        ca.aia_url = (request.POST.get('aia_url') or '').strip()
        ca.ocsp_url = (request.POST.get('ocsp_url') or '').strip()
        ca.sia_url = (request.POST.get('sia_url') or '').strip()
        ca.freshest_crl_url = (request.POST.get('freshest_crl_url') or '').strip()
        ca.issuer_alt_names = (request.POST.get('issuer_alt_names') or '').strip()
        ca.save(update_fields=[
            'crl_url', 'aia_url', 'ocsp_url', 'sia_url',
            'freshest_crl_url', 'issuer_alt_names',
        ])
        messages.success(request, 'Distribution points updated — applies to certs issued from now on')
        return redirect('ca_detail', ca_uuid=ca.uuid)

    certs = ca.certificates.order_by('-created_at')
    cert_text = ''
    if ca.cert_path.exists():
        cert_text = own_ca.cert_text(ca.cert_path)
    return render(request, 'dashboard/ca_detail.html', {
        'page': 'cas',
        'ca': ca,
        'certs': certs,
        'cert_text': cert_text,
        'crl_number': own_ca.read_crl_number(str(ca.uuid)),
        'latest_crl_export': ca.crl_exports.first(),
        # 'openssl' | 'capilite' — capilite = key in a CryptoPro container
        'ca_backend': own_ca.read_ca_backend(str(ca.uuid))[0],
    })


@superuser_required
def ca_delete_view(request, ca_uuid):
    if request.method != 'POST':
        return redirect('cas')
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)
    if ca.children.exists():
        messages.error(request, 'Cannot delete: has child CAs')
        return redirect('ca_detail', ca_uuid=ca.uuid)
    if ca.certificates.exists():
        messages.error(request, 'Cannot delete: has issued certificates. Revoke and delete them first.')
        return redirect('ca_detail', ca_uuid=ca.uuid)
    name = ca.name
    # Opt-in, because dropping the container destroys the key irreversibly and
    # nothing else in this app can: it is non-exportable, so no backup of the
    # storage directory brings it back. Left in place it stays in the provider's
    # keystore with nothing pointing at it any more.
    drop_container = bool(request.POST.get('drop_container'))
    was_capilite = own_ca.read_ca_backend(str(ca.uuid))[0] == 'capilite'
    own_ca.delete_ca_storage(str(ca.uuid), drop_container=drop_container)
    ca.delete()
    if was_capilite and drop_container:
        messages.success(request, f'CA "{name}" deleted, along with its CryptoPro key container')
    else:
        messages.success(request, f'CA "{name}" deleted')
    return redirect('cas')


@superuser_required
def ca_download_cert_view(request, ca_uuid):
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)
    if not ca.cert_path.exists():
        raise Http404('CA certificate not found on disk')
    return FileResponse(
        open(ca.cert_path, 'rb'),
        as_attachment=True,
        filename=f'{ca.name}.crt',
        content_type='application/x-pem-file',
    )


@superuser_required
def ca_export_p12_view(request, ca_uuid):
    """Export a CA's own certificate + private key (optionally + parent chain)
    as a PKCS#12 (.p12), with a selectable bag-encryption / MAC suite
    (standard AES or a GOST suite — kuznyechik / magma TK-26, or legacy
    gost89)."""
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)
    if request.method != 'POST':
        return redirect('ca_detail', ca_uuid=ca.uuid)
    password = request.POST.get('password') or ''
    if not password:
        messages.error(request, 'PKCS#12 export requires a passphrase')
        return redirect('ca_detail', ca_uuid=ca.uuid)
    pbe = request.POST.get('pbe') or 'standard'
    if pbe not in own_ca.CA_PKCS12_PBE_SUITES:
        messages.error(request, 'Unknown PKCS#12 encryption suite')
        return redirect('ca_detail', ca_uuid=ca.uuid)
    chain = _ca_chain_paths(ca.parent) if request.POST.get('include_chain') else []
    try:
        data = own_ca.pkcs12_export_ca(
            str(ca.uuid), password,
            friendly_name=ca.name, pbe=pbe, chain_paths=chain,
        )
    except OwnCAError as e:
        messages.error(request, f'PKCS#12 export failed: {e}')
        return redirect('ca_detail', ca_uuid=ca.uuid)
    resp = HttpResponse(data, content_type='application/x-pkcs12')
    suffix = '.pfx' if own_ca.read_ca_backend(str(ca.uuid))[0] == 'capilite' else '.p12'
    resp['Content-Disposition'] = f'attachment; filename="{ca.name}{suffix}"'
    return resp


@superuser_required
def ca_generate_crl_view(request, ca_uuid):
    if request.method != 'POST':
        return redirect('ca_detail', ca_uuid=ca_uuid)
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)
    try:
        own_ca.generate_crl(str(ca.uuid), revoked=_revoked_for_crl(ca))
    except OwnCAError as e:
        messages.error(request, f'CRL generation failed: {e}')
        return redirect('ca_detail', ca_uuid=ca.uuid)
    CrlExport.objects.create(
        ca=ca,
        crl_number=own_ca.read_crl_number(str(ca.uuid)),
        revoked_count=ca.certificates.filter(status='revoked').count(),
    )
    messages.success(request, f'CRL generated for "{ca.name}"')
    return redirect('ca_detail', ca_uuid=ca.uuid)


@superuser_required
def ca_download_crl_view(request, ca_uuid):
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)
    if not ca.crl_path.exists():
        # auto-generate on first download
        try:
            own_ca.generate_crl(str(ca.uuid), revoked=_revoked_for_crl(ca))
        except OwnCAError as e:
            messages.error(request, f'CRL not available: {e}')
            return redirect('ca_detail', ca_uuid=ca.uuid)
    return FileResponse(
        open(ca.crl_path, 'rb'),
        as_attachment=True,
        filename=f'{ca.name}.crl.pem',
        content_type='application/x-pem-file',
    )


# ---------------------------------------------------------------------------
# certificates
# ---------------------------------------------------------------------------

@superuser_required
def certificates_view(request):
    _expire_passed_certs()
    available_cas = _operator_cas(request)
    qs = Certificate.objects.select_related('issuer_ca').filter(
        issuer_ca__in=available_cas,
    )
    status = request.GET.get('status', '')
    if status:
        qs = qs.filter(status=status)
    ca_filter = request.GET.get('ca', '')
    if ca_filter:
        qs = qs.filter(issuer_ca__uuid=ca_filter)
    return render(request, 'dashboard/certificates.html', {
        'page': 'certificates',
        'certs': qs,
        'cas': available_cas,
        'status': status,
        'ca_filter': ca_filter,
    })


@superuser_required
def csr_parse_view(request):
    """Accept a CSR (PEM) via multipart upload (`csr_file`) or POST body
    (`csr_text`) and return its subject + requested SANs as JSON so the
    Issue form can auto-populate itself. Also echoes the raw PEM back so
    the client can stash it in a hidden input for later submission.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    csr_pem = b''
    upload = request.FILES.get('csr_file')
    if upload:
        csr_pem = upload.read()
    else:
        text = (request.POST.get('csr_text') or '').strip()
        if text:
            csr_pem = text.encode()

    if not csr_pem:
        return JsonResponse({'error': 'No CSR provided'}, status=400)

    try:
        fields = own_ca.parse_csr(csr_pem)
    except OwnCAError as e:
        return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({
        'ok': True,
        'fields': fields,
        'csr_pem': csr_pem.decode('utf-8', errors='replace'),
    })


@superuser_required
def cert_detail_view(request, cert_uuid):
    cert = get_object_or_404(Certificate.objects.select_related('issuer_ca'), uuid=cert_uuid)
    if not _operator_cas(request).filter(uuid=cert.issuer_ca.uuid).exists():
        return HttpResponseForbidden('CA not assigned to you.')
    cert_text = ''
    cert_pem = ''
    if cert.cert_path.exists():
        cert_text = own_ca.cert_text(cert.cert_path)
        cert_pem = cert.cert_path.read_text()
    renewals = cert.renewals.all().order_by('-created_at')
    # Build human-readable custom OID display
    custom_oid_display = []
    if cert.custom_oid_values and cert.cert_profile:
        label_map = {}
        for pof in cert.cert_profile.get_oid_fields_ordered():
            label_map[pof.oid_definition.field_key] = pof.oid_definition.label
        for key, val in cert.custom_oid_values.items():
            custom_oid_display.append({'oid': key, 'label': label_map.get(key, key), 'value': val})
    elif cert.custom_oid_values:
        for key, val in cert.custom_oid_values.items():
            custom_oid_display.append({'oid': key, 'label': key, 'value': val})
    return render(request, 'dashboard/cert_detail.html', {
        'page': 'certificates',
        'cert': cert,
        'cert_text': cert_text,
        'cert_pem': cert_pem,
        'reasons': REVOCATION_REASON_CHOICES,
        'renewals': renewals,
        'custom_oid_display': custom_oid_display,
        # 'openssl' | 'capilite' — a cert inherits its issuer CA's backend.
        # On 'capilite' the private key lives in a CryptoPro container, so the
        # key/CSR/bundle/TK-26 export paths below are hidden (see
        # cert_download_view for the matching server-side refusals).
        'ca_backend': own_ca.read_ca_backend(str(cert.issuer_ca.uuid))[0],
        'has_csr_file': cert.csr_path.exists(),
        # Only a server-generated key on a CryptoPro CA has a container of its
        # own — that is what the delete form offers to drop.
        'has_capi_container': own_ca.cert_has_capi_container(str(cert.uuid)),
    })


@superuser_required
def cert_download_view(request, cert_uuid, kind):
    cert = get_object_or_404(Certificate, uuid=cert_uuid)
    if not _operator_cas(request).filter(uuid=cert.issuer_ca_id).exists():
        return HttpResponseForbidden('CA not assigned to you.')

    # A CryptoPro-backed cert keeps its private key inside a CSP container, and
    # a server-generated one never produces a PKCS#10 either. The template hides
    # these actions, but a direct link must refuse them explicitly rather than
    # 404 ('key' / 'csr') or silently ship a keyless bundle ('bundle').
    on_capilite = own_ca.read_ca_backend(str(cert.issuer_ca.uuid))[0] == 'capilite'
    if on_capilite and kind in ('key', 'bundle'):
        messages.error(request, _CAPILITE_NO_KEY_EXPORT_MSG)
        return redirect('cert_detail', cert_uuid=cert.uuid)

    # Bundle exports — concat cert + key + chain into one file
    if kind == 'bundle':
        chain = _ca_chain_paths(cert.issuer_ca)
        try:
            data = own_ca.pem_bundle_export(str(cert.uuid), chain)
        except OwnCAError as e:
            raise Http404(str(e))
        resp = HttpResponse(data, content_type='application/x-pem-file')
        resp['Content-Disposition'] = f'attachment; filename="{cert.common_name}.bundle.pem"'
        return resp

    # PKCS#12 export — needs a passphrase, accept it from POST form
    if kind == 'p12':
        if request.method != 'POST':
            return redirect('cert_detail', cert_uuid=cert.uuid)
        password = request.POST.get('password') or ''
        if not password:
            messages.error(request, 'PKCS#12 export requires a passphrase')
            return redirect('cert_detail', cert_uuid=cert.uuid)
        gostkeybag = request.POST.get('gostkeybag') in ('1', 'on', 'true')
        if gostkeybag and not SystemSettings.get_solo().offer_gost_p12_export:
            messages.error(request, '.gost.p12 export is disabled by issuance mode settings.')
            return redirect('cert_detail', cert_uuid=cert.uuid)
        if gostkeybag and cert.key_alg not in ('gost2012_256', 'gost2012_512'):
            messages.error(request, 'TK-26 compatible PFX format requires a Gost-key')
            return redirect('cert_detail', cert_uuid=cert.uuid)
        cipher = request.POST.get('cipher') or 'kuznyechik-ctr-acpkm'
        if gostkeybag and cipher not in own_ca.GOST_PKCS12_CIPHERS:
            messages.error(request, 'Unsupported PKCS#12 GOST cipher selection')
            return redirect('cert_detail', cert_uuid=cert.uuid)
        chain = _ca_chain_paths(cert.issuer_ca)
        try:
            data = own_ca.pkcs12_export(
                str(cert.uuid), chain, password,
                friendly_name=cert.common_name,
                gostkeybag=gostkeybag,
                keybag_cipher=cipher,
                certbag_cipher=cipher,
            )
        except OwnCAError as e:
            messages.error(request, f'PKCS#12 export failed: {e}')
            return redirect('cert_detail', cert_uuid=cert.uuid)
        resp = HttpResponse(data, content_type='application/x-pkcs12')
        suffix = '.pfx' if on_capilite else ('.gost.p12' if gostkeybag else '.p12')
        resp['Content-Disposition'] = f'attachment; filename="{cert.common_name}{suffix}"'
        return resp

    # Plain file passthroughs
    if kind == 'cert':
        path = cert.cert_path
        filename = f'{cert.common_name}.crt'
    elif kind == 'key':
        if not cert.has_private_key:
            raise Http404('No private key for this certificate (issued from external CSR)')
        path = cert.key_path
        filename = f'{cert.common_name}.key'
    elif kind == 'csr':
        if on_capilite and not cert.csr_path.exists():
            messages.error(
                request,
                'This certificate was issued on the CryptoPro CSP backend with '
                'a server-generated key: the key is created directly inside a '
                'CSP container, so no PKCS#10 request exists for it.',
            )
            return redirect('cert_detail', cert_uuid=cert.uuid)
        path = cert.csr_path
        filename = f'{cert.common_name}.csr'
    else:
        raise Http404('Unknown download kind')
    if not path.exists():
        raise Http404(f'{kind} file missing on disk')
    return FileResponse(
        open(path, 'rb'),
        as_attachment=True,
        filename=filename,
        content_type='application/x-pem-file',
    )


@superuser_required
def cert_renew_view(request, cert_uuid):
    """Re-sign an existing CSR under a new Certificate row with new validity.

    The new cert reuses the original key (if stored) and CSR; only the
    validity dates and serial change. Profile/SAN/CRL/AIA come from the form
    or — if the form is empty — from the original cert and current CA.
    """
    if request.method != 'POST':
        return redirect('cert_detail', cert_uuid=cert_uuid)
    old = get_object_or_404(Certificate.objects.select_related('issuer_ca'), uuid=cert_uuid)
    if not _operator_cas(request).filter(uuid=old.issuer_ca.uuid).exists():
        return HttpResponseForbidden('CA not assigned to you.')
    if not old.csr_path.exists():
        messages.error(request, 'Cannot renew: original CSR missing on disk')
        return redirect('cert_detail', cert_uuid=old.uuid)

    days = max(1, int(request.POST.get('days') or settings.OWNCA_DEFAULT_CERT_DAYS))
    old_custom_oid_values = old.custom_oid_values or {}
    ext_lines = old.cert_profile.to_extfile_lines(old_custom_oid_values) if old.cert_profile else [
        'basicConstraints = critical, CA:FALSE',
        'keyUsage = critical, digitalSignature',
        'subjectKeyIdentifier = hash',
        'authorityKeyIdentifier = keyid:always',
    ]
    san_custom = old.cert_profile.get_san_custom(old_custom_oid_values) if old.cert_profile else {}
    # Fallback to stored san_dns/san_ip for certs issued before OID registry migration
    san_dns = san_custom.get('dns', []) or _split_san(old.san_dns)
    san_ip = san_custom.get('ip', []) or _split_san(old.san_ip)
    dp = _resolved_distribution_points(old.issuer_ca, old.cert_profile)
    spec = CertSpec(
        common_name=old.common_name,
        subject=old.subject,
        key_alg=old.key_alg,
        days=days,
        ext_lines=ext_lines,
        san_dns=san_dns,
        san_ip=san_ip,
        san_email=san_custom.get('email', []),
        san_uri=san_custom.get('uri', []),
        san_other=san_custom.get('otherName', []),
        **dp,
    )

    new = Certificate.objects.create(
        common_name=old.common_name,
        subject=old.subject,
        issuer_ca=old.issuer_ca,
        cert_profile=old.cert_profile,
        profile_name=old.profile_name,
        custom_oid_values=old_custom_oid_values,
        key_alg=old.key_alg,
        san_dns=old.san_dns,
        san_ip=old.san_ip,
        renewed_from=old,
    )
    try:
        info = own_ca.renew_certificate(
            str(old.issuer_ca.uuid), str(old.uuid), str(new.uuid), spec,
        )
    except OwnCAError as e:
        new.delete()
        own_ca.delete_cert_storage(str(new.uuid))
        messages.error(request, f'Renewal failed: {e}')
        return redirect('cert_detail', cert_uuid=old.uuid)

    new.serial_hex = info.get('serial_hex', '')
    new.fingerprint_sha256 = info.get('fingerprint_sha256', '')
    new.not_before = info.get('not_before')
    new.not_after = info.get('not_after')
    new.has_private_key = bool(info.get('has_private_key'))
    new.save()
    messages.success(
        request,
        f'Certificate "{old.common_name}" renewed (new serial {new.serial_hex})',
    )
    return redirect('cert_detail', cert_uuid=new.uuid)


@superuser_required
def cert_revoke_view(request, cert_uuid):
    if request.method != 'POST':
        return redirect('cert_detail', cert_uuid=cert_uuid)
    cert = get_object_or_404(Certificate, uuid=cert_uuid)
    if not _operator_cas(request).filter(uuid=cert.issuer_ca_id).exists():
        return HttpResponseForbidden('CA not assigned to you.')
    if cert.status == 'revoked':
        messages.warning(request, 'Certificate already revoked')
        return redirect('cert_detail', cert_uuid=cert.uuid)
    reason = request.POST.get('reason', 'unspecified')
    try:
        own_ca.revoke_certificate(str(cert.issuer_ca.uuid), str(cert.uuid), reason=reason)
    except OwnCAError as e:
        messages.error(request, f'Revocation failed: {e}')
        return redirect('cert_detail', cert_uuid=cert.uuid)
    # Record the revocation BEFORE rebuilding the CRL: a CryptoPro CA has no
    # openssl index.txt, so its CRL is built from _revoked_for_crl() — i.e. from
    # this very DB row. Generating first would leave the just-revoked cert out
    # of the CRL until some later regeneration.
    cert.status = 'revoked'
    cert.revoked_at = timezone.now()
    cert.revocation_reason = reason
    cert.save()
    try:
        own_ca.generate_crl(str(cert.issuer_ca.uuid), revoked=_revoked_for_crl(cert.issuer_ca))
    except OwnCAError as e:
        messages.error(
            request,
            f'Certificate "{cert.common_name}" revoked, but CRL regeneration '
            f'failed: {e}',
        )
        return redirect('cert_detail', cert_uuid=cert.uuid)
    CrlExport.objects.create(
        ca=cert.issuer_ca,
        crl_number=own_ca.read_crl_number(str(cert.issuer_ca.uuid)),
        revoked_count=cert.issuer_ca.certificates.filter(status='revoked').count(),
    )
    messages.success(request, f'Certificate "{cert.common_name}" revoked')
    return redirect('cert_detail', cert_uuid=cert.uuid)


@superuser_required
def cert_delete_view(request, cert_uuid):
    if request.method != 'POST':
        return redirect('certificates')
    cert = get_object_or_404(Certificate, uuid=cert_uuid)
    if not _operator_cas(request).filter(uuid=cert.issuer_ca_id).exists():
        return HttpResponseForbidden('CA not assigned to you.')
    name = cert.common_name
    # Opt-in, same as for a CA: the container holds a key nothing can export.
    drop_container = bool(request.POST.get('drop_container'))
    had_container = own_ca.cert_has_capi_container(str(cert.uuid))
    own_ca.delete_cert_storage(str(cert.uuid), drop_container=drop_container)
    cert.delete()
    if had_container and drop_container:
        messages.success(
            request,
            f'Certificate "{name}" deleted from index, along with its CryptoPro key container')
    else:
        messages.success(request, f'Certificate "{name}" deleted from index')
    return redirect('certificates')


# ---------------------------------------------------------------------------
# system: admins (Django users), password policy (validators), config, maintenance
# ---------------------------------------------------------------------------



def _env_var_rows() -> list:
    """Rows for the environment-variable table on the configuration page.

    The value shown is the one Django actually resolved, not raw ``os.environ``:
    settings.py coerces types and can veto a flag (OWNCA_CRYPTOPRO_ENABLED is
    forced off on an image without the build marker), and the operator needs to
    see what took effect — not what was requested.

    ``source`` separates a value the operator set from the built-in fallback.
    On a page whose job is "what is this instance running with", that
    distinction is half the answer.
    """
    import os

    def row(name, description, value, *, secret=False):
        return {
            'name': name,
            'description': description,
            # A licence serial is not something to render verbatim on a screen
            # that may be shared or screenshotted.
            'value': cryptopro.mask_serial(value) if secret else value,
            'source': 'env' if os.environ.get(name) is not None else 'default',
        }

    rows = [
        row('OWNCA_STORAGE_DIR',
            _('Filesystem path where CA and cert material is stored'),
            str(settings.OWNCA_STORAGE_DIR)),
        row('OWNCA_OPENSSL_BIN',
            _('Path to the openssl binary (gost-engine loaded via OPENSSL_CONF)'),
            settings.OWNCA_OPENSSL_BIN),
        row('OWNCA_DEFAULT_KEY_ALG',
            _('Default key algorithm for new CAs and certs'),
            settings.OWNCA_DEFAULT_KEY_ALG),
        row('OWNCA_DEFAULT_CA_DAYS',
            _('Default CA validity in days'), settings.OWNCA_DEFAULT_CA_DAYS),
        row('OWNCA_DEFAULT_CERT_DAYS',
            _('Default end-entity cert validity in days'),
            settings.OWNCA_DEFAULT_CERT_DAYS),
        row('OWNCA_CRL_DISTRIBUTION',
            _('Public URL where CRLs will be served (informational)'),
            settings.OWNCA_CRL_DISTRIBUTION),
        row('OPENSSL_CONF',
            _('Path to openssl.cnf that loads gost-engine'),
            os.environ.get('OPENSSL_CONF', '')),
    ]
    # Listed only on an image that actually carries CryptoPro — elsewhere they
    # are six rows of noise describing something that cannot be switched on.
    if cryptopro.available():
        rows += [
            row('OWNCA_CRYPTOPRO_ENABLED',
                _('Route GOST operations through CryptoPro CSP'),
                settings.OWNCA_CRYPTOPRO_ENABLED),
            row('OWNCA_CRYPTOPRO_LICENSE',
                _('CryptoPro licence serial (masked; empty = 90-day demo)'),
                settings.OWNCA_CRYPTOPRO_LICENSE, secret=True),
            row('OWNCA_CRYPTOPRO_GAMMA_DIR',
                _('DRBG gamma directory (CPSD pools)'),
                settings.OWNCA_CRYPTOPRO_GAMMA_DIR),
            row('OWNCA_CRYPTOPRO_ROOT',
                _('CryptoPro install root'), settings.OWNCA_CRYPTOPRO_ROOT),
            row('OWNCA_CRYPTOPRO_SHIM_BIN',
                _('Path to the ownca_capi CAPILite bridge'),
                settings.OWNCA_CRYPTOPRO_SHIM_BIN),
            row('OWNCA_CRYPTOPRO_MARKER',
                _('Build marker proving CryptoPro is in the image'),
                settings.OWNCA_CRYPTOPRO_MARKER),
        ]
    return rows


@superuser_required
def configuration_view(request):
    sys_settings = SystemSettings.get_solo()
    if request.method == 'POST':
        sys_settings.allow_server_key_generation = request.POST.get('allow_server_key_generation') == 'on'
        sys_settings.allow_gost_keys = request.POST.get('allow_gost_keys') == 'on'
        sys_settings.allow_rsa_keys = request.POST.get('allow_rsa_keys') == 'on'
        sys_settings.allow_ecdsa_keys = request.POST.get('allow_ecdsa_keys') == 'on'
        # The .gost.p12 row is hidden while CryptoPro is on (TK-26 is an
        # openssl+gost-engine format the provider cannot produce). A hidden
        # checkbox posts nothing, so reading it here would clear the stored flag
        # on every save — leave it untouched instead, ready for the day the
        # backend is switched off again.
        if not cryptopro.enabled():
            sys_settings.offer_gost_p12_export = request.POST.get('offer_gost_p12_export') == 'on'
        sys_settings.disable_cert_profile_protection = request.POST.get('disable_cert_profile_protection') == 'on'
        sys_settings.save()
        messages.success(request, _('Issuance settings saved.'))
        return redirect('configuration')
    return render(request, 'dashboard/configuration.html', {
        'page': 'configuration',
        'storage_dir': str(settings.OWNCA_STORAGE_DIR),
        'default_key_alg': settings.OWNCA_DEFAULT_KEY_ALG,
        'default_ca_days': settings.OWNCA_DEFAULT_CA_DAYS,
        'default_cert_days': settings.OWNCA_DEFAULT_CERT_DAYS,
        'crl_distribution': settings.OWNCA_CRL_DISTRIBUTION,
        'sys_settings': sys_settings,
        'env_rows': _env_var_rows(),
    })


def _cryptopro_panel_context() -> dict:
    """Context the CryptoPro panels need. Shared by the Maintenance page that
    renders them and kept out of the page view so the probing stays in one
    place."""
    return {
        'prov': cryptopro.status(),
        'lic': cryptopro.license_info(),
        'gamma': cryptopro.gamma_status(),
        'cp_settings': CryptoProSettings.get_solo(),
        'gamma_dir': str(cryptopro.gamma_dir()),
    }


@superuser_required
def maintenance_view(request):
    openssl_version = own_ca.openssl_version()
    ctx = {
        'page': 'maintenance',
        'storage_dir': str(settings.OWNCA_STORAGE_DIR),
        'openssl_version': openssl_version,
        'gost_engine_loaded': own_ca.gost_engine_loaded(),
    }
    # The CryptoPro panels live here too — with the certified backend on, this
    # IS the crypto backend. Probing costs a `csptest` subprocess and a stat of
    # the gamma pools, so it only runs on an image that actually has CryptoPro.
    if cryptopro.available():
        ctx.update(_cryptopro_panel_context())
    return render(request, 'dashboard/maintenance.html', ctx)


# ---------------------------------------------------------------------------
# Certificate Profiles (data-driven extension templates)
# ---------------------------------------------------------------------------

_CERT_PROFILE_KU_FIELDS = [
    'ku_digital_signature', 'ku_non_repudiation', 'ku_key_encipherment',
    'ku_data_encipherment', 'ku_key_agreement', 'ku_key_cert_sign',
    'ku_crl_sign', 'ku_encipher_only', 'ku_decipher_only',
]


def _opt_int(post, field):
    """Return the int value of a POST field, or None if blank/invalid."""
    raw = (post.get(field) or '').strip()
    if not raw:
        return None
    try:
        v = int(raw)
        return v if v >= 0 else None
    except (TypeError, ValueError):
        return None


def _cert_profile_from_post(post) -> dict:
    """Extract CertProfile fields from a POST dict (excludes OID field M2M)."""
    kw = {
        'name': (post.get('name') or '').strip(),
        'display_name': (post.get('display_name') or '').strip(),
        'description': (post.get('description') or '').strip(),
        'eku': (post.get('eku') or '').strip(),
        'eku_critical': post.get('eku_critical') in ('on', '1', 'true'),
        'ku_critical': post.get('ku_critical') in ('on', '1', 'true'),
        'is_ca_profile': post.get('is_ca_profile') in ('on', '1', 'true'),
        'extra_extensions': (post.get('extra_extensions') or '').strip(),
        # Profile-level distribution-point overrides
        'crl_url': (post.get('crl_url') or '').strip(),
        'aia_url': (post.get('aia_url') or '').strip(),
        'ocsp_url': (post.get('ocsp_url') or '').strip(),
        'sia_url': (post.get('sia_url') or '').strip(),
        'freshest_crl_url': (post.get('freshest_crl_url') or '').strip(),
        # Name Constraints
        'name_constraints_permitted': (post.get('name_constraints_permitted') or '').strip(),
        'name_constraints_excluded': (post.get('name_constraints_excluded') or '').strip(),
        'name_constraints_critical': post.get('name_constraints_critical') in ('on', '1', 'true'),
        # Policy Constraints + Inhibit Any-Policy
        'policy_constraints_require_explicit': _opt_int(post, 'policy_constraints_require_explicit'),
        'policy_constraints_inhibit_mapping': _opt_int(post, 'policy_constraints_inhibit_mapping'),
        'inhibit_any_policy': _opt_int(post, 'inhibit_any_policy'),
        # SKI / AKI toggles
        'include_subject_key_identifier': post.get('include_subject_key_identifier') in ('on', '1', 'true'),
        'include_authority_key_identifier': post.get('include_authority_key_identifier') in ('on', '1', 'true'),
        'aki_include_issuer': post.get('aki_include_issuer') in ('on', '1', 'true'),
    }
    for f in _CERT_PROFILE_KU_FIELDS:
        kw[f] = post.get(f) in ('on', '1', 'true')
    return kw


def _save_profile_oid_fields(profile, post):
    """Update a profile's OID field assignments from POST data.

    Expects a hidden input ``oid_fields_json`` with JSON:
    ``[{"id": <pk>, "required": <bool>}, ...]``
    """
    import json as _json
    from .models import CustomOidDefinition, ProfileOidField
    raw = (post.get('oid_fields_json') or '').strip()
    entries = []
    if raw:
        try:
            entries = _json.loads(raw)
        except (ValueError, TypeError):
            pass
    ProfileOidField.objects.filter(profile=profile).delete()
    for idx, entry in enumerate(entries):
        try:
            od = CustomOidDefinition.objects.get(pk=int(entry.get('id', 0)))
        except (CustomOidDefinition.DoesNotExist, ValueError, TypeError):
            continue
        ProfileOidField.objects.create(
            profile=profile, oid_definition=od,
            required=bool(entry.get('required')), order=idx,
        )


def _collect_custom_oid_values(post, cert_profile) -> dict:
    """Collect custom OID values from POST data for the given profile."""
    values = {}
    if not cert_profile:
        return values
    for pof in cert_profile.get_oid_fields_ordered():
        key = pof.oid_definition.field_key
        val = (post.get(f'custom_oid_{key}') or '').strip()
        if val:
            values[key] = val
    return values


def _validate_required_oid_fields(custom_oid_values, cert_profile):
    """Return label of first missing required OID field, or None."""
    if not cert_profile:
        return None
    for pof in cert_profile.get_oid_fields_ordered():
        if pof.required and not custom_oid_values.get(pof.oid_definition.field_key):
            return pof.oid_definition.label
    return None


@superuser_required
def cert_profiles_view(request):
    if request.method == 'POST':
        kw = _cert_profile_from_post(request.POST)
        if not kw.get('name') or not kw.get('display_name'):
            messages.error(request, 'Name and display name are required')
            return redirect('cert_profiles')
        if CertProfile.objects.filter(name=kw['name']).exists():
            messages.error(request, f'Profile "{kw["name"]}" already exists')
            return redirect('cert_profiles')
        cp = CertProfile.objects.create(**kw)
        _save_profile_oid_fields(cp, request.POST)
        messages.success(request, f'Certificate profile "{kw["display_name"]}" created')
        return redirect('cert_profiles')

    import json as _json
    all_oid_defs = [
        {'id': od.pk, 'oid': od.oid, 'label': od.label,
         'placement': od.placement, 'asn1_type': od.asn1_type}
        for od in CustomOidDefinition.objects.all()
    ]
    return render(request, 'dashboard/cert_profiles.html', {
        'page': 'cert_profiles',
        'cert_profiles': CertProfile.objects.annotate(
            certs_using=Count('certificates', distinct=True),
            requests_using=Count('certificate_requests', distinct=True),
        ),
        'all_oid_defs_json': _json.dumps(all_oid_defs),
    })


@superuser_required
def cert_profile_detail_view(request, cp_id):
    cp = get_object_or_404(CertProfile, pk=cp_id)
    if request.method == 'POST':
        kw = _cert_profile_from_post(request.POST)
        if not kw.get('name') or not kw.get('display_name'):
            messages.error(request, 'Name and display name are required')
            return redirect('cert_profile_detail', cp_id=cp.pk)
        if CertProfile.objects.filter(name=kw['name']).exclude(pk=cp.pk).exists():
            messages.error(request, f'Name "{kw["name"]}" already taken')
            return redirect('cert_profile_detail', cp_id=cp.pk)
        for f, v in kw.items():
            setattr(cp, f, v)
        cp.save()
        _save_profile_oid_fields(cp, request.POST)
        messages.success(request, f'Profile "{cp.display_name}" saved')
        return redirect('cert_profile_detail', cp_id=cp.pk)

    import json as _json
    # Preview extension lines (with placeholder values for custom OIDs)
    preview_oid_values = {}
    for pof in cp.get_oid_fields_ordered():
        preview_oid_values[pof.oid_definition.field_key] = '<value>'
    preview = cp.to_extfile_lines(preview_oid_values if preview_oid_values else None)

    # Build JSON for the OID field selector
    assigned = [
        {'id': pof.oid_definition.pk, 'required': pof.required}
        for pof in cp.get_oid_fields_ordered()
    ]
    all_oid_defs = [
        {'id': od.pk, 'oid': od.oid, 'label': od.label,
         'placement': od.placement, 'asn1_type': od.asn1_type}
        for od in CustomOidDefinition.objects.all()
    ]
    return render(request, 'dashboard/cert_profile_detail.html', {
        'page': 'cert_profiles',
        'cp': cp,
        'preview': preview,
        'certs_using': cp.certificates.count(),
        'requests_using': cp.certificate_requests.count(),
        'assigned_oids_json': _json.dumps(assigned),
        'all_oid_defs_json': _json.dumps(all_oid_defs),
        # What a CryptoPro-backed CA would refuse in this profile — surfaced
        # while it is being edited, not when an operator finally tries to use it
        'capilite_problems': cp.capilite_incompatibilities(),
    })


@superuser_required
def cert_profile_delete_view(request, cp_id):
    if request.method != 'POST':
        return redirect('cert_profiles')
    cp = get_object_or_404(CertProfile, pk=cp_id)
    if cp.certificates.exists() or cp.certificate_requests.exists():
        messages.error(request, f'Cannot delete: profile is used by {cp.certificates.count()} cert(s)')
        return redirect('cert_profile_detail', cp_id=cp.pk)
    name = cp.display_name
    cp.delete()
    messages.success(request, f'Profile "{name}" deleted')
    return redirect('cert_profiles')


def _unique_name(model, field, base):
    """Return a copy-name based on `base` that does not collide with any
    existing row's `field`. Tries `<base>_copy`, `<base>_copy_2`, ..."""
    candidate = f'{base}_copy'
    n = 2
    while model.objects.filter(**{field: candidate}).exists():
        candidate = f'{base}_copy_{n}'
        n += 1
    return candidate


@superuser_required
def cert_profile_copy_view(request, cp_id):
    if request.method != 'POST':
        return redirect('cert_profile_detail', cp_id=cp_id)
    src = get_object_or_404(CertProfile, pk=cp_id)
    new_name = _unique_name(CertProfile, 'name', src.name)
    # Duplicate the row by clearing PK and re-saving
    oid_links = list(src.profile_oid_fields.all())
    src.pk = None
    src.name = new_name
    src.display_name = f'{src.display_name} (copy)'
    src.save()
    from .models import ProfileOidField
    for link in oid_links:
        ProfileOidField.objects.create(
            profile=src,
            oid_definition=link.oid_definition,
            required=link.required,
            order=link.order,
        )
    messages.success(request, f'Profile copied as "{src.display_name}"')
    return redirect('cert_profile_detail', cp_id=src.pk)


# ---------------------------------------------------------------------------
# Custom certificate issuance (free-form)
# ---------------------------------------------------------------------------

_FREE_FORM_KU_BITS = [
    ('digitalSignature', _('Digital signature')),
    ('nonRepudiation', _('Non-repudiation')),
    ('keyEncipherment', _('Key encipherment')),
    ('dataEncipherment', _('Data encipherment')),
    ('keyAgreement', _('Key agreement')),
    ('keyCertSign', _('Certificate signing')),
    ('cRLSign', _('CRL signing')),
    ('encipherOnly', _('Encipher only')),
    ('decipherOnly', _('Decipher only')),
]


def _build_free_form_payload(post) -> tuple[list[str], dict]:
    """Translate the Free Request form POST into ``(ext_lines, free_form_data)``.

    ``ext_lines`` is the rendered openssl.cnf extension block that issuance
    will use verbatim. ``free_form_data`` captures the same payload plus SAN
    lists and DP overrides for redisplay during operator review."""
    lines = ['basicConstraints = critical, CA:FALSE']

    ku_bits = [b for b, _ in _FREE_FORM_KU_BITS if post.get(f'ku_{b}')]
    if ku_bits:
        crit = 'critical, ' if post.get('ku_critical') else ''
        lines.append(f'keyUsage = {crit}{", ".join(ku_bits)}')

    eku = (post.get('eku') or '').strip()
    if eku:
        crit = 'critical, ' if post.get('eku_critical') else ''
        lines.append(f'extendedKeyUsage = {crit}{eku}')

    # `= none` when unchecked: OpenSSL 3.x adds SKI/AKI by itself unless the
    # extension is explicitly disabled (see CertProfile.to_extfile_lines).
    if post.get('include_subject_key_identifier'):
        lines.append('subjectKeyIdentifier = hash')
    else:
        lines.append('subjectKeyIdentifier = none')
    if post.get('include_authority_key_identifier'):
        aki = 'keyid:always'
        if post.get('aki_include_issuer'):
            aki += ', issuer:always'
        lines.append(f'authorityKeyIdentifier = {aki}')
    else:
        lines.append('authorityKeyIdentifier = none')

    # Custom OID rows: post fields oid_row_oid_<i>, oid_row_type_<i>, oid_row_value_<i>
    for key in post.keys():
        if not key.startswith('oid_row_oid_'):
            continue
        idx = key[len('oid_row_oid_'):]
        oid = (post.get(f'oid_row_oid_{idx}') or '').strip()
        asn1 = (post.get(f'oid_row_type_{idx}') or 'UTF8').strip()
        val = (post.get(f'oid_row_value_{idx}') or '').strip()
        if not oid or not val:
            continue
        from .models import ASN1_TYPE_MAP
        asn1_full = ASN1_TYPE_MAP.get(asn1, 'UTF8String')
        lines.append(f'{oid} = ASN1:{asn1_full}:{val}')

    extra = (post.get('extra_extensions') or '').strip()
    if extra:
        for raw in extra.splitlines():
            line = raw.strip()
            if line:
                lines.append(line)

    free_form_data = {
        'ext_lines': lines,
        'san_email': _split_san(post.get('san_email') or ''),
        'san_uri': _split_san(post.get('san_uri') or ''),
        'san_other': [
            line.strip() for line in (post.get('san_other') or '').splitlines()
            if line.strip()
        ],
        'crl_url': (post.get('crl_url') or '').strip(),
        'aia_url': (post.get('aia_url') or '').strip(),
        'ocsp_url': (post.get('ocsp_url') or '').strip(),
        'sia_url': (post.get('sia_url') or '').strip(),
        'freshest_crl_url': (post.get('freshest_crl_url') or '').strip(),
    }
    return lines, free_form_data


@superuser_required
def custom_cert_issue_view(request):
    """Custom certificate issuance — bypasses cert-profile constraints.
    Picks the issuing CA and cert profile from selectboxes and issues
    the certificate immediately (no CSR review queue).
    Gated by ``SystemSettings.disable_cert_profile_protection``."""
    cas = _operator_cas(request)
    sys_settings = SystemSettings.get_solo()

    def _family_allowed(alg: str) -> bool:
        return _key_family_allowed(alg, sys_settings)

    if request.method != 'POST':
        key_alg_choices_with_family = [
            (v, label, key_alg_family(v)) for v, label in KEY_ALG_CHOICES
            if _family_allowed(v)
        ]
        # Tag each CA with its crypto backend so the form can narrow the GOST
        # paramset list: gost-engine and the certified provider do not
        # necessarily offer the same sets, and a set the provider refuses is a
        # dead option. Probed once, and only if some CA is actually CryptoPro-
        # backed.
        ca_list = list(cas)
        for c in ca_list:
            c.crypto_backend = own_ca.read_ca_backend(str(c.uuid))[0]
        any_capilite = any(c.crypto_backend == 'capilite' for c in ca_list)
        return render(request, 'dashboard/custom_cert_issue.html', {
            'page': 'custom_cert_issue',
            'cas': ca_list,
            'key_alg_choices': key_alg_choices_with_family,
            'gost_paramsets_256': own_ca.GOST_PARAMSET_CHOICES_256,
            'gost_paramsets_512': own_ca.GOST_PARAMSET_CHOICES_512,
            'capi_paramsets_256': (own_ca.capi_supported_paramsets('gost2012_256')
                                   if any_capilite else []),
            'capi_paramsets_512': (own_ca.capi_supported_paramsets('gost2012_512')
                                   if any_capilite else []),
            'default_gost_paramset': own_ca.DEFAULT_GOST_PARAMSET,
            'asn1_type_choices': ASN1_TYPE_CHOICES,
            'ku_bits': _FREE_FORM_KU_BITS,
            'allow_server_key_generation': sys_settings.allow_server_key_generation,
            'allow_free_form': sys_settings.disable_cert_profile_protection,
        })

    if not cas.exists():
        messages.error(request, 'No CAs available — create one first')
        return redirect('cas')

    ca_uuid = request.POST.get('ca')
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)

    # The CSR (if any) is the authoritative source for the certificate's
    # identity: whatever is actually attached to *this* POST, never the form's
    # common_name/subject fields — those may only reflect an earlier "Parse
    # CSR" preview and no longer match if the operator picked a different
    # file afterwards without re-parsing.
    csr_pem = None
    csr_text = (request.POST.get('csr_text') or '').strip()
    if csr_text:
        csr_pem = csr_text.encode()
    else:
        upload = request.FILES.get('csr_file')
        if upload:
            csr_pem = upload.read()

    if csr_pem:
        try:
            csr_fields = own_ca.parse_csr(csr_pem)
        except OwnCAError as e:
            messages.error(request, f'Could not parse the uploaded CSR: {e}')
            return redirect('custom_cert_issue')
        cn = (csr_fields.get('common_name') or '').strip()
        if not cn:
            messages.error(request, 'The uploaded CSR has no Common Name')
            return redirect('custom_cert_issue')
        subject = _subject_from_csr_fields(csr_fields)
    else:
        cn = (request.POST.get('common_name') or '').strip()
        if not cn:
            messages.error(request, 'Common Name is required')
            return redirect('custom_cert_issue')
        subject = _build_subject(cn, request)

    if not csr_pem and not sys_settings.allow_server_key_generation:
        messages.error(request, 'Server-side key generation is disabled. Please upload a CSR.')
        return redirect('custom_cert_issue')

    cert_profile_id = (request.POST.get('cert_profile') or '').strip()
    cert_profile = None
    if cert_profile_id:
        cert_profile = CertProfile.objects.filter(
            pk=cert_profile_id, is_ca_profile=False,
        ).first()

    # Free-form issuance (no profile) bypasses cert-profile constraints and is
    # only permitted when explicitly enabled. Otherwise a profile is required.
    if cert_profile is None and not sys_settings.disable_cert_profile_protection:
        messages.error(
            request,
            'Free-form certificate issuance is disabled — select a certificate profile.',
        )
        return redirect('custom_cert_issue')

    # With a CSR attached, its own subject public key decides the algorithm —
    # the form's selector only describes whatever was parsed earlier and may no
    # longer match the file in this request. The family it yields is read from
    # the CSR's public key alone, so a request signed under another family
    # cannot skew it.
    if csr_pem:
        csr_family = csr_fields.get('key_family') or ''
        if not csr_family:
            messages.error(
                request,
                'Could not determine the key algorithm of the uploaded CSR '
                f'("{csr_fields.get("public_key_algorithm") or "unknown"}") — '
                'refusing to issue.'
            )
            return redirect('custom_cert_issue')
        key_alg = csr_fields.get('key_alg') or csr_family
        alg_source = ' (from the uploaded CSR)'
    else:
        key_alg = request.POST.get('key_alg', ca.key_alg)
        alg_source = ''

    if not _family_allowed(key_alg):
        messages.error(request, f'Key algorithm "{key_alg}"{alg_source} is disabled by issuance mode settings.')
        return redirect('custom_cert_issue')
    if key_alg_family(key_alg) != key_alg_family(ca.key_alg):
        messages.error(
            request,
            f'Key algorithm "{key_alg}"{alg_source} is not compatible with the '
            f'issuing CA (CA uses "{ca.key_alg}"). A CA can only sign '
            f'certificates from the same key family.'
        )
        return redirect('custom_cert_issue')
    days = max(1, int(request.POST.get('days') or 365))

    paramset = (request.POST.get('paramset') or own_ca.DEFAULT_GOST_PARAMSET).strip()
    if csr_pem or not key_alg.startswith('gost2012'):
        paramset = own_ca.DEFAULT_GOST_PARAMSET

    ext_lines, free_form_data = _build_free_form_payload(request.POST)
    if cert_profile:
        custom_oid_values = _collect_custom_oid_values(request.POST, cert_profile)
        missing = _validate_required_oid_fields(custom_oid_values, cert_profile)
        if missing:
            messages.error(request, f'Custom OID field "{missing}" is required')
            return redirect('custom_cert_issue')
        profile_ext_lines = cert_profile.to_extfile_lines(custom_oid_values)
        san_custom = cert_profile.get_san_custom(custom_oid_values)
        san_dns = san_custom.get('dns', [])
        san_ip = san_custom.get('ip', [])
        san_email = san_custom.get('email', [])
        san_uri = san_custom.get('uri', [])
        san_other = san_custom.get('otherName', [])
        combined_ext_lines = profile_ext_lines + [
            line for line in ext_lines
            if not any(line.startswith(pl.split('=')[0].strip())
                       for pl in profile_ext_lines)
        ]
        dp = _resolved_distribution_points(ca, cert_profile)
    else:
        custom_oid_values = {}
        san_dns = _split_san(request.POST.get('san_dns', ''))
        san_ip = _split_san(request.POST.get('san_ip', ''))
        san_email = [e.strip() for e in (request.POST.get('san_email') or '').replace(',', '\n').splitlines() if e.strip()]
        san_uri = [u.strip() for u in (request.POST.get('san_uri') or '').replace(',', '\n').splitlines() if u.strip()]
        san_other = [o.strip() for o in (request.POST.get('san_other') or '').splitlines() if o.strip()]
        combined_ext_lines = ext_lines or [
            'basicConstraints = critical, CA:FALSE',
            'keyUsage = critical, digitalSignature',
            'subjectKeyIdentifier = hash',
            'authorityKeyIdentifier = keyid:always',
        ]
        dp = _resolved_distribution_points(ca, None)

    spec = CertSpec(
        common_name=cn,
        subject=subject,
        key_alg=key_alg,
        days=days,
        ext_lines=combined_ext_lines,
        san_dns=san_dns,
        san_ip=san_ip,
        san_email=san_email,
        san_uri=san_uri,
        san_other=san_other,
        paramset=paramset,
        **dp,
    )

    cert = Certificate.objects.create(
        common_name=cn,
        subject=subject,
        issuer_ca=ca,
        cert_profile=cert_profile,
        profile_name=cert_profile.display_name if cert_profile else 'Free-form',
        custom_oid_values=custom_oid_values,
        key_alg=key_alg,
        san_dns=','.join(san_dns),
        san_ip=','.join(san_ip),
    )
    try:
        info = own_ca.issue_certificate(str(ca.uuid), str(cert.uuid), spec, csr_pem=csr_pem)
    except OwnCAError as e:
        cert.delete()
        own_ca.delete_cert_storage(str(cert.uuid))
        messages.error(request, f'Certificate issuance failed: {e}')
        return redirect('custom_cert_issue')

    cert.subject = info.get('subject', subject)
    cert.serial_hex = info.get('serial_hex', '')
    cert.fingerprint_sha256 = info.get('fingerprint_sha256', '')
    cert.not_before = info.get('not_before')
    cert.not_after = info.get('not_after')
    cert.has_private_key = bool(info.get('has_private_key'))
    cert.save()
    messages.success(request, f'Certificate "{cn}" issued')
    return redirect('cert_detail', cert_uuid=cert.uuid)


_KU_LABELS = [
    ('ku_digital_signature', 'digitalSignature'),
    ('ku_non_repudiation', 'nonRepudiation'),
    ('ku_key_encipherment', 'keyEncipherment'),
    ('ku_data_encipherment', 'dataEncipherment'),
    ('ku_key_agreement', 'keyAgreement'),
    ('ku_key_cert_sign', 'keyCertSign'),
    ('ku_crl_sign', 'cRLSign'),
    ('ku_encipher_only', 'encipherOnly'),
    ('ku_decipher_only', 'decipherOnly'),
]


def _profile_preview_payload(p, ca):
    """Build the JSON payload describing the effective values that will be
    embedded in a cert issued under (ca, profile). Used by the issue form
    preview panel."""
    def _dp(field):
        own = (getattr(p, field, '') or '').strip()
        if own:
            return {'value': own, 'source': 'profile'}
        ca_val = (getattr(ca, field, '') or '').strip()
        if ca_val:
            return {'value': ca_val, 'source': 'ca'}
        return None

    ku_bits = [
        {'name': name, 'set': bool(getattr(p, attr))}
        for attr, name in _KU_LABELS
    ]
    oid_fields = [
        {
            'oid': pof.oid_definition.oid,
            'label': pof.oid_definition.label,
            'asn1_type': pof.oid_definition.asn1_type,
            'placement': pof.oid_definition.placement,
            'required': pof.required,
            'field_key': pof.oid_definition.field_key,
        }
        for pof in p.get_oid_fields_ordered()
    ]
    return {
        'id': p.pk,
        'display_name': p.display_name,
        'name': p.name,
        'description': p.description,
        'ku': p.ku_display,
        'ku_bits': ku_bits,
        'ku_critical': p.ku_critical,
        'ku_names': p.ku_openssl_names,
        'eku': p.eku,
        'eku_critical': p.eku_critical,
        'is_ca_profile': p.is_ca_profile,
        'distribution_points': {
            'crl_url': _dp('crl_url'),
            'aia_url': _dp('aia_url'),
            'ocsp_url': _dp('ocsp_url'),
            'sia_url': _dp('sia_url'),
            'freshest_crl_url': _dp('freshest_crl_url'),
        },
        'issuer_alt_names': _split_lines(ca.issuer_alt_names),
        'name_constraints_permitted': _split_lines(p.name_constraints_permitted),
        'name_constraints_excluded': _split_lines(p.name_constraints_excluded),
        'name_constraints_critical': p.name_constraints_critical,
        'policy_constraints_require_explicit': p.policy_constraints_require_explicit,
        'policy_constraints_inhibit_mapping': p.policy_constraints_inhibit_mapping,
        'inhibit_any_policy': p.inhibit_any_policy,
        'include_subject_key_identifier': p.include_subject_key_identifier,
        'include_authority_key_identifier': p.include_authority_key_identifier,
        'aki_include_issuer': p.aki_include_issuer,
        'extra_extensions': p.extra_extensions,
        # Non-empty => a CryptoPro-backed CA will refuse this profile. The issue
        # form warns on selection instead of letting the operator fill the whole
        # form and hit the refusal on submit.
        'capilite_problems': p.capilite_incompatibilities(),
        'custom_oid_fields': oid_fields,
        'preview_lines': p.to_extfile_lines(),
    }


@superuser_required
def ca_cert_profiles_api(request, ca_uuid):
    """Return non-CA cert profiles available under this CA, with DP previews
    resolved against it."""
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)
    profiles = CertProfile.objects.filter(is_ca_profile=False).order_by('display_name')
    data = [_profile_preview_payload(p, ca) for p in profiles]
    return JsonResponse({'profiles': data})


@superuser_required
def ca_all_cert_profiles_api(request, ca_uuid):
    """Return all non-CA cert profiles, with DP previews resolved against the
    given CA."""
    ca = get_object_or_404(CertificateAuthority, uuid=ca_uuid)
    profiles = CertProfile.objects.filter(is_ca_profile=False).order_by('display_name')
    data = [_profile_preview_payload(p, ca) for p in profiles]
    return JsonResponse({'profiles': data})


@superuser_required
def maintenance_refresh_api(request):
    """Re-parse all certs from disk and write metadata back."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    refreshed = 0
    errors = 0
    for cert in Certificate.objects.all():
        if cert.cert_path.exists():
            try:
                _refresh_cert_metadata(cert)
                refreshed += 1
            except Exception as e:
                log.warning('refresh failed for %s: %s', cert.uuid, e)
                errors += 1
    _expire_passed_certs()
    return JsonResponse({'refreshed': refreshed, 'errors': errors})


@superuser_required
def maintenance_rebuild_crls_api(request):
    """Regenerate the CRL for every enabled CA and record each export."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    rebuilt = 0
    errors = 0
    for ca in CertificateAuthority.objects.filter(is_enabled=True):
        try:
            own_ca.generate_crl(str(ca.uuid), revoked=_revoked_for_crl(ca))
            own_ca.export_crl(str(ca.uuid), ca.name)
        except OwnCAError as e:
            log.warning('CRL rebuild failed for %s: %s', ca.uuid, e)
            errors += 1
            continue
        CrlExport.objects.create(
            ca=ca,
            crl_number=own_ca.read_crl_number(str(ca.uuid)),
            revoked_count=ca.certificates.filter(status='revoked').count(),
        )
        rebuilt += 1
    return JsonResponse({'rebuilt': rebuilt, 'errors': errors})


# ---------------------------------------------------------------------------
# CryptoPro CSP
# ---------------------------------------------------------------------------

@superuser_required
def cryptopro_view(request):
    """CryptoPro CSP management: provider status, license, and DRBG gamma
    (remaining counter + upload / stand-only generation)."""
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'set_license':
            serial = (request.POST.get('license_serial') or '').strip()
            cps = CryptoProSettings.get_solo()
            cps.license_serial = serial
            cps.save(update_fields=['license_serial'])
            if not serial:
                messages.success(request, _('License serial cleared — falling back to the env value or the built-in demo license.'))
            elif not cryptopro.available():
                messages.warning(request, _('Serial saved, but CryptoPro is not installed in this image, so it was not activated.'))
            else:
                try:
                    cryptopro.apply_license(serial)
                    cps.license_applied_at = timezone.now()
                    cps.save(update_fields=['license_applied_at'])
                    messages.success(request, _('CryptoPro license activated.'))
                except cryptopro.CryptoProError as e:
                    messages.error(request, _('License activation failed: %(err)s') % {'err': e})
            return redirect('maintenance')

        if action == 'upload_gamma':
            f = request.FILES.get('gamma_file')
            raw = request.POST.get('gamma_raw') == 'on'
            mode = 'replace' if request.POST.get('gamma_mode') == 'replace' else 'append'
            if not f:
                messages.error(request, _('No gamma file selected.'))
            else:
                try:
                    segs = cryptopro.ingest_upload(f.read(), raw=raw, mode=mode)
                    messages.success(request, _('Gamma written (%(mode)s): %(n)d segments.') % {'mode': mode, 'n': segs})
                except cryptopro.CryptoProError as e:
                    messages.error(request, _('Gamma upload failed: %(err)s') % {'err': e})
            return redirect('maintenance')

        if action == 'generate_gamma':
            try:
                n = int(request.POST.get('gamma_segments') or '0')
            except (TypeError, ValueError):
                n = 0
            mode = 'replace' if request.POST.get('gamma_mode') == 'replace' else 'append'
            if n <= 0:
                messages.error(request, _('Enter a positive number of segments.'))
            else:
                try:
                    pool = cryptopro.generate_gamma(n)
                    cryptopro.write_gamma(pool, mode=mode)
                    messages.success(request, _('Generated %(n)d test gamma segments (%(mode)s).') % {'n': n, 'mode': mode})
                except cryptopro.CryptoProError as e:
                    messages.error(request, _('Gamma generation failed: %(err)s') % {'err': e})
            return redirect('maintenance')

        return redirect('maintenance')

    # GET has nothing of its own to render any more: the panels moved to
    # Maintenance. The URL is kept because the forms above post to it (and
    # because bookmarks and the webhelp link to it).
    return redirect('maintenance')


@superuser_required
def cryptopro_status_api(request):
    """JSON snapshot for the live gamma counter / status refresh button."""
    gamma = cryptopro.gamma_status()
    prov = cryptopro.status()
    return JsonResponse({
        'available': prov.available,
        'enabled': prov.enabled,
        'draws_remaining': gamma.draws_remaining,
        'bytes_per_draw': gamma.bytes_per_draw,
        'gamma_ok': gamma.ok,
        'providers': prov.providers,
    })


