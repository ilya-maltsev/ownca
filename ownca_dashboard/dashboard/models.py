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

import json
import re
import uuid

from django.conf import settings
from django.db import models


KEY_ALG_CHOICES = [
    ('gost2012_256', 'GOST R 34.10-2012 (256 bit)'),
    ('gost2012_512', 'GOST R 34.10-2012 (512 bit)'),
    ('rsa:2048', 'RSA 2048'),
    ('rsa:4096', 'RSA 4096'),
    ('ec:P-256', 'ECDSA P-256 (secp256r1)'),
    ('ec:P-384', 'ECDSA P-384 (secp384r1)'),
    ('ed25519', 'Ed25519'),
]


def key_alg_family(key_alg: str) -> str:
    """Return the cryptographic family of a KEY_ALG_CHOICES value.

    A CA may only sign leaf certificates whose key belongs to the same
    family — e.g. an RSA CA cannot issue a GOST cert and vice versa.
    """
    if not key_alg:
        return ''
    if key_alg.startswith('gost'):
        return 'gost'
    if key_alg.startswith('rsa'):
        return 'rsa'
    if key_alg.startswith('ec'):
        return 'ec'
    if key_alg.startswith('ed25519'):
        return 'ed25519'
    return key_alg

CA_TYPE_CHOICES = [
    ('root', 'Root CA'),
    ('intermediate', 'Intermediate CA'),
]

PLACEMENT_CHOICES = [
    ('extension', 'Extension'),
    ('san_dns', 'SAN DNS name'),
    ('san_ip', 'SAN IP address'),
    ('san_email', 'SAN email'),
    ('san_uri', 'SAN URI'),
    ('san_othername', 'SAN otherName'),
]

MULTI_VALUE_PLACEMENTS = {'san_dns', 'san_ip', 'san_uri'}

ASN1_TYPE_CHOICES = [
    ('UTF8', 'UTF8String'),
    ('IA5', 'IA5String'),
    ('PRINTABLE', 'PrintableString'),
    ('INT', 'INTEGER'),
    ('BOOL', 'BOOLEAN'),
]

ASN1_TYPE_MAP = {
    'UTF8': 'UTF8String',
    'IA5': 'IA5String',
    'PRINTABLE': 'PrintableString',
    'INT': 'INTEGER',
    'BOOL': 'BOOLEAN',
}


class CustomOidDefinition(models.Model):
    """Registry of known OID / SAN field definitions. Each entry describes a
    single field that operators fill in at certificate issuance time. Profiles
    reference these via M2M (ProfileOidField)."""
    oid = models.CharField(
        max_length=128, blank=True, default='',
        help_text='Dotted OID (e.g. 1.2.643.100.3). Empty for built-in SAN types (DNS, IP, email, URI).',
    )
    label = models.CharField(max_length=128)
    description = models.TextField(blank=True)
    asn1_type = models.CharField(max_length=16, choices=ASN1_TYPE_CHOICES, default='UTF8')
    placement = models.CharField(max_length=24, choices=PLACEMENT_CHOICES, default='extension')
    is_builtin = models.BooleanField(
        default=False,
        help_text='Built-in definitions cannot be deleted via UI.',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['label']
        verbose_name = 'Custom OID Definition'

    def __str__(self):
        if self.oid:
            return f'{self.label} ({self.oid})'
        return self.label

    @property
    def field_key(self) -> str:
        """Key used in custom_oid_values dict and form field names."""
        return self.oid if self.oid else self.placement

class CertProfile(models.Model):
    """Data-driven certificate extension profile. Admins create/edit these via
    the web UI; each row defines the Key Usage bits, Extended Key Usage OIDs,
    and references OID field definitions from the CustomOidDefinition registry."""
    name = models.CharField(max_length=64, unique=True)
    display_name = models.CharField(max_length=128)
    description = models.TextField(blank=True)

    # Key Usage bits (OID 2.5.29.15) — each maps to one bit in the KU bitstring
    ku_digital_signature = models.BooleanField(default=False)
    ku_non_repudiation = models.BooleanField(default=False)
    ku_key_encipherment = models.BooleanField(default=False)
    ku_data_encipherment = models.BooleanField(default=False)
    ku_key_agreement = models.BooleanField(default=False)
    ku_key_cert_sign = models.BooleanField(default=False)
    ku_crl_sign = models.BooleanField(default=False)
    ku_encipher_only = models.BooleanField(default=False)
    ku_decipher_only = models.BooleanField(default=False)
    ku_critical = models.BooleanField(default=True, help_text='RFC 5280: MUST be critical')

    # Extended Key Usage (OID 2.5.29.37) — comma-separated openssl names or raw OIDs
    eku = models.TextField(
        blank=True, default='',
        help_text='Comma-separated: serverAuth, clientAuth, codeSigning, '
                  'emailProtection, timeStamping, OCSPSigning, or raw OIDs like 1.3.6.1.5.5.7.3.8',
    )
    eku_critical = models.BooleanField(default=False)

    # Extra raw openssl extension lines for power users
    extra_extensions = models.TextField(
        blank=True,
        help_text='Raw openssl.cnf extension lines, one per line (e.g. tlsfeature = status_request)',
    )

    # OID fields from registry (replaces old custom_oid_fields JSONField)
    oid_fields = models.ManyToManyField(
        'CustomOidDefinition', through='ProfileOidField', blank=True,
        help_text='OID field definitions assigned to this profile.',
    )

    # Name Constraints (§4.2.1.10 — OID 2.5.29.30). One openssl entry per line.
    # Format per line: "<TYPE>:<VALUE>" e.g. "DNS:.example.org" or "IP:10.0.0.0/255.0.0.0"
    name_constraints_permitted = models.TextField(
        blank=True, default='',
        help_text='Permitted subtrees (one entry per line, e.g. DNS:.example.org).',
    )
    name_constraints_excluded = models.TextField(
        blank=True, default='',
        help_text='Excluded subtrees (one entry per line, e.g. DNS:.bad.example.org).',
    )
    name_constraints_critical = models.BooleanField(default=True)

    # Policy Constraints (§4.2.1.11 — OID 2.5.29.36). Negative = absent.
    policy_constraints_require_explicit = models.IntegerField(
        null=True, blank=True,
        help_text='requireExplicitPolicy (≥0). Empty = not present.',
    )
    policy_constraints_inhibit_mapping = models.IntegerField(
        null=True, blank=True,
        help_text='inhibitPolicyMapping (≥0). Empty = not present.',
    )

    # Inhibit Any-Policy (§4.2.1.14 — OID 2.5.29.54). Empty = not present.
    inhibit_any_policy = models.IntegerField(
        null=True, blank=True,
        help_text='SkipCerts integer for inhibitAnyPolicy. Empty = not present.',
    )

    # Distribution-point overrides (per-profile, fall back to CA value)
    crl_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='Profile-level CRL URL — overrides the CA value when set.',
    )
    aia_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='Profile-level caIssuers URL — overrides the CA value when set.',
    )
    ocsp_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='Profile-level OCSP responder URL — overrides the CA value when set.',
    )
    sia_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='Profile-level Subject Information Access URL — overrides the CA value when set.',
    )
    freshest_crl_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='Profile-level delta-CRL URL — overrides the CA value when set.',
    )

    # SKI / AKI customization. Defaults reproduce the previous hardcoded behaviour.
    include_subject_key_identifier = models.BooleanField(default=True)
    include_authority_key_identifier = models.BooleanField(default=True)
    aki_include_issuer = models.BooleanField(
        default=False,
        help_text='Add issuer:always to authorityKeyIdentifier.',
    )

    # DEPRECATED — kept for migration compatibility. Use oid_fields M2M instead.
    custom_oid_fields = models.JSONField(
        default=list, blank=True,
        help_text='DEPRECATED. Legacy JSON custom OID fields.',
    )

    is_ca_profile = models.BooleanField(
        default=False,
        help_text='If True, basicConstraints = CA:TRUE (for intermediate CA certs)',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['display_name']
        verbose_name = 'Certificate Profile'

    def __str__(self):
        return self.display_name

    @staticmethod
    def _split_multi(raw: str) -> list[str]:
        """Split comma/semicolon/newline-delimited string into individual values.

        Spaces inside a value are preserved — needed for SAN URI / otherName
        values that may legitimately contain spaces or parentheses.
        """
        if not raw:
            return []
        return [p.strip() for p in re.split(r'[,;\r\n]+', raw) if p.strip()]

    def get_oid_fields_ordered(self):
        """Return ProfileOidField queryset with related oid_definition, ordered."""
        return (self.profile_oid_fields
                .select_related('oid_definition')
                .order_by('order', 'pk'))

    def to_extfile_lines(self, custom_oid_values: dict | None = None) -> list[str]:
        """Render the openssl extension lines for an extfile.cnf.

        Only **extension**-placement OID fields are rendered here.
        SAN-placement fields are handled by :meth:`get_san_custom` and merged
        into the SAN section by ``own_ca._build_extfile``.

        Distribution-point extensions (CDP, AIA, freshestCRL, SIA) and
        issuerAltName are NOT emitted here — they are CA-resolved values
        that ``own_ca._build_extfile`` injects from the ``CertSpec``.
        """
        lines = []
        # Basic Constraints
        if self.is_ca_profile:
            lines.append('basicConstraints = critical, CA:TRUE')
        else:
            lines.append('basicConstraints = critical, CA:FALSE')

        # Key Usage
        ku_bits = []
        if self.ku_digital_signature:
            ku_bits.append('digitalSignature')
        if self.ku_non_repudiation:
            ku_bits.append('nonRepudiation')
        if self.ku_key_encipherment:
            ku_bits.append('keyEncipherment')
        if self.ku_data_encipherment:
            ku_bits.append('dataEncipherment')
        if self.ku_key_agreement:
            ku_bits.append('keyAgreement')
        if self.ku_key_cert_sign:
            ku_bits.append('keyCertSign')
        if self.ku_crl_sign:
            ku_bits.append('cRLSign')
        if self.ku_encipher_only:
            ku_bits.append('encipherOnly')
        if self.ku_decipher_only:
            ku_bits.append('decipherOnly')
        if ku_bits:
            crit = 'critical, ' if self.ku_critical else ''
            lines.append(f'keyUsage = {crit}{", ".join(ku_bits)}')

        # Extended Key Usage
        if self.eku.strip():
            crit = 'critical, ' if self.eku_critical else ''
            lines.append(f'extendedKeyUsage = {crit}{self.eku.strip()}')

        # Standard identifiers (toggleable; defaults preserve old behaviour)
        if self.include_subject_key_identifier:
            lines.append('subjectKeyIdentifier = hash')
        if self.include_authority_key_identifier:
            aki = 'keyid:always'
            if self.aki_include_issuer:
                aki += ', issuer:always'
            lines.append(f'authorityKeyIdentifier = {aki}')

        # Policy Constraints (RFC 5280 §4.2.1.11) — emitted before raw extras
        # so an operator can override via extra_extensions if needed.
        pc_parts = []
        if self.policy_constraints_require_explicit is not None and self.policy_constraints_require_explicit >= 0:
            pc_parts.append(f'requireExplicitPolicy:{self.policy_constraints_require_explicit}')
        if self.policy_constraints_inhibit_mapping is not None and self.policy_constraints_inhibit_mapping >= 0:
            pc_parts.append(f'inhibitPolicyMapping:{self.policy_constraints_inhibit_mapping}')
        if pc_parts:
            lines.append('policyConstraints = critical, ' + ', '.join(pc_parts))

        # Inhibit Any-Policy (§4.2.1.14)
        if self.inhibit_any_policy is not None and self.inhibit_any_policy >= 0:
            lines.append(f'inhibitAnyPolicy = critical, {self.inhibit_any_policy}')

        # Name Constraints (§4.2.1.10) — split textareas, "<TYPE>:<VALUE>" per line
        nc_parts = []
        for raw in self.name_constraints_permitted.splitlines():
            entry = raw.strip()
            if entry:
                nc_parts.append(f'permitted;{entry}')
        for raw in self.name_constraints_excluded.splitlines():
            entry = raw.strip()
            if entry:
                nc_parts.append(f'excluded;{entry}')
        if nc_parts:
            crit = 'critical, ' if self.name_constraints_critical else ''
            lines.append(f'nameConstraints = {crit}{", ".join(nc_parts)}')

        # Extra raw lines
        if self.extra_extensions.strip():
            for line in self.extra_extensions.strip().splitlines():
                if line.strip():
                    lines.append(line.strip())

        # Extension-placement OID fields from registry
        if custom_oid_values:
            for pof in self.get_oid_fields_ordered():
                od = pof.oid_definition
                if od.placement != 'extension':
                    continue
                value = custom_oid_values.get(od.field_key, '').strip()
                if not value:
                    continue
                asn1_type = ASN1_TYPE_MAP.get(od.asn1_type, 'UTF8String')
                lines.append(f'{od.oid} = ASN1:{asn1_type}:{value}')

        return lines

    def resolve_distribution_point(self, ca, field: str) -> str:
        """Return the effective value for one of the DP fields:
        ``crl_url``, ``aia_url``, ``ocsp_url``, ``sia_url``, ``freshest_crl_url``.

        Per-profile value wins over CA value. Empty string means "omit".
        """
        own = (getattr(self, field, '') or '').strip()
        if own:
            return own
        return (getattr(ca, field, '') or '').strip()

    def get_san_custom(self, custom_oid_values: dict | None = None) -> dict:
        """Return SAN entries from OID fields assigned to this profile.

        Returns ``{'dns': [...], 'ip': [...], 'email': [...], 'uri': [...],
        'otherName': [...]}`` — each list contains values ready for the
        ``[ san_section ]`` in an openssl extfile.
        """
        entries: dict[str, list[str]] = {
            'dns': [], 'ip': [], 'email': [], 'uri': [], 'otherName': [],
        }
        if not custom_oid_values:
            return entries
        for pof in self.get_oid_fields_ordered():
            od = pof.oid_definition
            placement = od.placement
            if placement == 'extension':
                continue
            value = custom_oid_values.get(od.field_key, '').strip()
            if not value:
                continue
            if placement == 'san_dns':
                entries['dns'].extend(self._split_multi(value))
            elif placement == 'san_ip':
                entries['ip'].extend(self._split_multi(value))
            elif placement == 'san_uri':
                entries['uri'].extend(self._split_multi(value))
            elif placement == 'san_email':
                entries['email'].append(value)
            elif placement == 'san_othername':
                asn1_type = ASN1_TYPE_MAP.get(od.asn1_type, 'UTF8String')
                entries['otherName'].append(f'{od.oid};{asn1_type}:{value}')
        return entries

    @property
    def ku_display(self) -> str:
        """Short human-readable KU summary."""
        bits = []
        if self.ku_digital_signature: bits.append('dS')
        if self.ku_non_repudiation: bits.append('nR')
        if self.ku_key_encipherment: bits.append('kE')
        if self.ku_data_encipherment: bits.append('dE')
        if self.ku_key_agreement: bits.append('kA')
        if self.ku_key_cert_sign: bits.append('kCS')
        if self.ku_crl_sign: bits.append('cRL')
        if self.ku_encipher_only: bits.append('eO')
        if self.ku_decipher_only: bits.append('dO')
        return ', '.join(bits) or '(none)'

    @property
    def ku_openssl_names(self) -> list[str]:
        """Canonical openssl KU names (matches keyUsage values in extfile.cnf).

        Used to compare a CSR's requested Key Usage against what the profile
        will actually emit at signing time.
        """
        bits = []
        if self.ku_digital_signature: bits.append('digitalSignature')
        if self.ku_non_repudiation: bits.append('nonRepudiation')
        if self.ku_key_encipherment: bits.append('keyEncipherment')
        if self.ku_data_encipherment: bits.append('dataEncipherment')
        if self.ku_key_agreement: bits.append('keyAgreement')
        if self.ku_key_cert_sign: bits.append('keyCertSign')
        if self.ku_crl_sign: bits.append('cRLSign')
        if self.ku_encipher_only: bits.append('encipherOnly')
        if self.ku_decipher_only: bits.append('decipherOnly')
        return bits


class ProfileOidField(models.Model):
    """Through model linking CertProfile to CustomOidDefinition with per-profile
    settings (required flag, display order)."""
    profile = models.ForeignKey(
        CertProfile, on_delete=models.CASCADE,
        related_name='profile_oid_fields',
    )
    oid_definition = models.ForeignKey(
        CustomOidDefinition, on_delete=models.CASCADE,
        related_name='profile_usages',
    )
    required = models.BooleanField(default=False)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order', 'pk']
        unique_together = [('profile', 'oid_definition')]

    def __str__(self):
        return f'{self.profile.name} → {self.oid_definition.label}'

CERT_STATUS_CHOICES = [
    ('active', 'Active'),
    ('revoked', 'Revoked'),
    ('expired', 'Expired'),
]

REVOCATION_REASON_CHOICES = [
    ('unspecified', 'Unspecified'),
    ('keyCompromise', 'Key compromise'),
    ('CACompromise', 'CA compromise'),
    ('affiliationChanged', 'Affiliation changed'),
    ('superseded', 'Superseded'),
    ('cessationOfOperation', 'Cessation of operation'),
    ('certificateHold', 'Certificate hold'),
]

class CertificateAuthority(models.Model):
    """A Certificate Authority — root or intermediate. All key/cert material lives
    on disk under OWNCA_STORAGE_DIR/cas/<uuid>/, this row is the index entry."""
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, db_index=True, unique=True)
    ca_type = models.CharField(max_length=16, choices=CA_TYPE_CHOICES, default='root')
    parent = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.PROTECT,
        related_name='children',
    )
    subject = models.CharField(max_length=512)
    key_alg = models.CharField(max_length=32, choices=KEY_ALG_CHOICES, default='gost2012_256')
    serial_hex = models.CharField(max_length=64, blank=True)
    fingerprint_sha256 = models.CharField(max_length=128, blank=True)
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    crl_url = models.CharField(max_length=512, blank=True, help_text='CRL Distribution Point URL embedded in issued certs')
    aia_url = models.CharField(max_length=512, blank=True, help_text='Authority Info Access caIssuers URL embedded in issued certs')
    ocsp_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='OCSP responder URL embedded as authorityInfoAccess OCSP entry (RFC 6960).',
    )
    sia_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='Subject Information Access URL — caRepository for sub-CAs (RFC 5280 §4.2.2.2).',
    )
    freshest_crl_url = models.CharField(
        max_length=512, blank=True, default='',
        help_text='URL of delta CRL (freshestCRL extension, RFC 5280 §4.2.1.15).',
    )
    issuer_alt_names = models.TextField(
        blank=True, default='',
        help_text='issuerAltName entries embedded in issued certs (one per line, e.g. email:ca@example.org).',
    )
    is_enabled = models.BooleanField(default=True)
    require_otp_for_issuance = models.BooleanField(
        default=False,
        help_text='Require TOTP code from operator before issuing certificates under this CA.',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'Certificate Authority'
        verbose_name_plural = 'Certificate Authorities'

    def __str__(self):
        return self.name

    @property
    def storage_dir(self):
        from django.conf import settings
        from pathlib import Path
        return Path(settings.OWNCA_STORAGE_DIR) / 'cas' / str(self.uuid)

    @property
    def cert_path(self):
        return self.storage_dir / 'ca.crt'

    @property
    def key_path(self):
        return self.storage_dir / 'ca.key'

    @property
    def crl_path(self):
        return self.storage_dir / 'crl.pem'

    @property
    def issued_count(self):
        return self.certificates.count()

    @property
    def active_count(self):
        return self.certificates.filter(status='active').count()

    @property
    def revoked_count(self):
        return self.certificates.filter(status='revoked').count()


class Certificate(models.Model):
    """An end-entity certificate (or a sub-CA cert). Issued by a CA, signed and
    stored on disk under OWNCA_STORAGE_DIR/certs/<uuid>/."""
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    common_name = models.CharField(max_length=255, db_index=True)
    subject = models.CharField(max_length=512)
    issuer_ca = models.ForeignKey(
        CertificateAuthority, on_delete=models.PROTECT,
        related_name='certificates',
    )
    serial_hex = models.CharField(max_length=64, db_index=True)
    cert_profile = models.ForeignKey(
        CertProfile, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='certificates',
    )
    profile_name = models.CharField(max_length=128, blank=True, help_text='Snapshot of profile display_name at issue time')
    custom_oid_values = models.JSONField(
        default=dict, blank=True,
        help_text='Snapshot of custom OID values at issue time: {oid: value}',
    )
    key_alg = models.CharField(max_length=32, choices=KEY_ALG_CHOICES, default='gost2012_256')
    san_dns = models.TextField(blank=True, help_text='Comma- or newline-separated DNS names')
    san_ip = models.TextField(blank=True, help_text='Comma- or newline-separated IPs')
    fingerprint_sha256 = models.CharField(max_length=128, blank=True)
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    has_private_key = models.BooleanField(default=False)
    status = models.CharField(max_length=16, choices=CERT_STATUS_CHOICES, default='active', db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(max_length=32, choices=REVOCATION_REASON_CHOICES, blank=True)
    renewed_from = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='renewals',
        help_text='Original certificate this one was renewed from',
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='owned_certificates',
        help_text='User who requested this certificate (null for pre-RBAC or operator-initiated certs)',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.common_name} ({self.serial_hex})'

    @property
    def storage_dir(self):
        from django.conf import settings
        from pathlib import Path
        return Path(settings.OWNCA_STORAGE_DIR) / 'certs' / str(self.uuid)

    @property
    def cert_path(self):
        return self.storage_dir / 'cert.pem'

    @property
    def key_path(self):
        return self.storage_dir / 'key.pem'

    @property
    def csr_path(self):
        return self.storage_dir / 'csr.pem'


class CrlExport(models.Model):
    """History of CRL generations per CA."""
    ca = models.ForeignKey(CertificateAuthority, on_delete=models.CASCADE, related_name='crl_exports')
    generated_at = models.DateTimeField(auto_now_add=True)
    crl_number = models.CharField(max_length=64, blank=True)
    revoked_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-generated_at']

    def __str__(self):
        return f'CRL #{self.crl_number} for {self.ca.name}'


# ---------------------------------------------------------------------------
# RBAC: UserProfile + CertificateRequest
# ---------------------------------------------------------------------------

ROLE_CHOICES = [
    ('user', 'User'),
    ('operator', 'Operator'),
    ('admin', 'Admin'),
]

# Group names used in Django auth. Must match the choices above with 's' suffix.
ROLE_GROUPS = {'user': 'users', 'operator': 'operators', 'admin': 'admins'}

AUTH_METHOD_CHOICES = [
    ('password', 'Login / Password'),
    ('mtls', 'Mutual TLS (client certificate)'),
    ('otp', 'One-Time Password'),
]


class UserProfile(models.Model):
    """Per-user metadata: IP/CIDR restrictions, role (derived from Django Group),
    and future auth-method flags for mTLS / OTP."""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='profile',
    )
    allowed_cidrs = models.TextField(
        blank=True,
        help_text='One CIDR per line (e.g. 10.0.0.0/8). Empty = allow from any IP.',
    )
    auth_methods = models.CharField(
        max_length=64, default='password',
        help_text='Comma-separated list of enabled auth methods (password, mtls, otp).',
    )
    assigned_cas = models.ManyToManyField(
        'CertificateAuthority', blank=True,
        related_name='assigned_operators',
        help_text='CAs this operator can use. Empty = no access to any CA.',
    )
    notes = models.TextField(blank=True, help_text='Admin notes about this user.')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'User Profile'

    def __str__(self):
        return f'{self.user.username} ({self.role})'

    @property
    def role(self) -> str:
        """Return the user's highest role based on group membership."""
        groups = set(self.user.groups.values_list('name', flat=True))
        if 'admins' in groups:
            return 'admin'
        if 'operators' in groups:
            return 'operator'
        if 'users' in groups:
            return 'user'
        return 'none'

    def get_available_cas(self):
        """Return the enabled CAs explicitly assigned to this operator.

        Empty assignment means **no access** to any CA — this is the safe
        default so a newly created operator cannot act on every CA until an
        admin explicitly grants access.
        """
        return self.assigned_cas.filter(is_enabled=True)

    def cidr_list(self) -> list:
        """Return parsed CIDR strings, or empty list (= no restriction)."""
        if not self.allowed_cidrs.strip():
            return []
        return [line.strip() for line in self.allowed_cidrs.splitlines() if line.strip()]


CERT_REQUEST_STATUS_CHOICES = [
    ('pending', 'Pending Review'),
    ('approved', 'Approved'),
    ('rejected', 'Rejected'),
]


class CertificateRequest(models.Model):
    """A user's request to have a certificate issued. Created by USERs,
    reviewed (approved/rejected) by OPERATORs or ADMINs."""
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='certificate_requests',
    )
    common_name = models.CharField(max_length=255)
    subject = models.CharField(max_length=512, blank=True)
    cert_profile = models.ForeignKey(
        CertProfile, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='certificate_requests',
    )
    key_alg = models.CharField(max_length=32, choices=KEY_ALG_CHOICES, default='gost2012_256')
    san_dns = models.TextField(blank=True)
    san_ip = models.TextField(blank=True)
    days = models.IntegerField(default=365)
    csr_pem = models.TextField(blank=True, help_text='PEM-encoded CSR uploaded by the user')
    notes = models.TextField(blank=True, help_text='User notes for the operator')

    is_free_form = models.BooleanField(
        default=False,
        help_text='Free-form request bypassing cert-profile constraints — '
                  'extension lines, SAN entries, and DP overrides are stored '
                  'in free_form_data.',
    )
    free_form_data = models.JSONField(
        default=dict, blank=True,
        help_text='Self-contained payload for free-form requests. Keys: '
                  '"ext_lines" (list[str]), "san_email"/"san_uri"/"san_other" '
                  '(list[str]), "crl_url"/"aia_url"/"ocsp_url"/"sia_url"/'
                  '"freshest_crl_url" (str, blank = inherit from CA).',
    )

    status = models.CharField(max_length=16, choices=CERT_REQUEST_STATUS_CHOICES, default='pending')
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='reviewed_requests',
    )
    review_notes = models.TextField(blank=True)
    issued_certificate = models.OneToOneField(
        Certificate, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='source_request',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.common_name} ({self.get_status_display()})'


class SystemSettings(models.Model):
    """Singleton row holding system-wide toggles editable from the
    Configuration page. Use :meth:`get_solo` to fetch (or create) the row."""
    disable_cert_profile_protection = models.BooleanField(
        default=False,
        help_text='When enabled, any role can submit a free-form certificate '
                  'request bypassing the cert-profile constraints (KU, EKU, '
                  'extensions, OIDs).',
    )

    # Issuance mode toggles
    allow_server_key_generation = models.BooleanField(
        default=True,
        help_text='When disabled, server-side key generation is refused; '
                  'only externally supplied CSRs are accepted.',
    )
    allow_gost_keys = models.BooleanField(
        default=True,
        help_text='Allow GOST R 34.10-2012 key families. '
                  'Requires OWNCA_GOST_ENGINE=on.',
    )
    allow_rsa_keys = models.BooleanField(
        default=True,
        help_text='Allow RSA key families.',
    )
    allow_ecdsa_keys = models.BooleanField(
        default=False,
        help_text='Allow ECDSA (P-256, P-384) and Ed25519 key families.',
    )
    offer_gost_p12_export = models.BooleanField(
        default=True,
        help_text='Offer TK-26 compatible .gost.p12 export option '
                  '(RFC 9337/9548). Requires GOST keys to be enabled.',
    )

    class Meta:
        verbose_name = 'System Settings'
        verbose_name_plural = 'System Settings'

    def __str__(self):
        return 'System Settings'

    @classmethod
    def get_solo(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
