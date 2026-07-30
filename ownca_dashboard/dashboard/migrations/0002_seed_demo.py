"""Seed data for the OwnCA free-demo application.

Reproduces, in a single RunPython, the data that the previous 22 migrations
accumulated across:
  0006  seed CertProfile rows
  0010  update default-profile KU bits
  0012  backfill admin → all CAs assignment
  0017  seed CustomOidDefinition + ProfileOidField
  0020  localise profile display_name / description to Russian
"""
from django.db import migrations


# ── All cert profiles (final state after 0006 + 0010 + 0017 + 0020) ─────────

PROFILES = [
    {
        'name': 'server',
        'display_name': 'TLS-сервер',
        'description': 'Стандартный серверный TLS-сертификат.',
        'ku_digital_signature': True,
        'ku_key_encipherment': True,
        'ku_key_agreement': True,
        'eku': 'serverAuth',
    },
    {
        'name': 'client',
        'display_name': 'TLS-клиент',
        'description': 'Клиентская аутентификация TLS (mTLS).',
        'ku_digital_signature': True,
        'ku_key_encipherment': True,
        'ku_data_encipherment': True,
        'ku_key_agreement': True,
        'eku': 'clientAuth',
    },
    {
        'name': 'server_client',
        'display_name': 'TLS-сервер + клиент',
        'description': 'serverAuth и clientAuth EKU. Для mTLS-серверов.',
        'ku_digital_signature': True,
        'ku_key_encipherment': True,
        'eku': 'serverAuth, clientAuth',
    },
    {
        'name': 'code_signing',
        'display_name': 'Подпись кода',
        'description': 'Подпись исполняемого кода.',
        'ku_digital_signature': True,
        'eku': 'codeSigning',
    },
    {
        'name': 'user',
        'display_name': 'Пользователь / Email',
        'description': 'Пользовательский сертификат: клиентская аутентификация + защита эл. почты S/MIME.',
        'ku_digital_signature': True,
        'ku_key_encipherment': True,
        'eku': 'clientAuth, emailProtection',
    },
    {
        'name': 'smime_sign',
        'display_name': 'Подпись S/MIME',
        'description': 'Подпись эл. почты с nonRepudiation для юридической значимости.',
        'ku_digital_signature': True,
        'ku_non_repudiation': True,
        'eku': 'emailProtection',
    },
    {
        'name': 'timestamping',
        'display_name': 'Метка времени (TSA)',
        'description': 'Штамп времени RFC 3161. EKU отмечен как критичный.',
        'ku_digital_signature': True,
        'eku': 'timeStamping',
        'eku_critical': True,
    },
    {
        'name': 'vpn',
        'display_name': 'VPN / IPSec',
        'description': 'Сертификат конечной точки VPN с серверной и клиентской аутентификацией.',
        'ku_digital_signature': True,
        'eku': 'serverAuth, clientAuth',
    },
    {
        'name': 'smartcard_logon',
        'display_name': 'Вход по смарт-карте',
        'description': 'Вход Windows по смарт-карте с UPN в SAN.',
        'ku_digital_signature': True,
        'ku_key_encipherment': True,
        'ku_critical': True,
        'eku': 'clientAuth, 1.3.6.1.4.1.311.20.2.2',
    },
    {
        'name': 'user_login',
        'display_name': 'Пользователь + Login ID',
        'description': 'Клиентская аутентификация с пользовательским идентификатором в SAN otherName.',
        'ku_digital_signature': True,
        'ku_key_encipherment': True,
        'ku_critical': True,
        'eku': 'clientAuth',
    },
]


# ── Built-in OID definitions (from 0017 BUILTIN_OIDS) ────────────────────────

BUILTIN_OIDS = [
    {'oid': '', 'label': 'DNS Names', 'asn1_type': 'IA5', 'placement': 'san_dns'},
    {'oid': '', 'label': 'IP Addresses', 'asn1_type': 'IA5', 'placement': 'san_ip'},
    {'oid': '', 'label': 'Email (SAN)', 'asn1_type': 'IA5', 'placement': 'san_email'},
    {'oid': '', 'label': 'URI (SAN)', 'asn1_type': 'IA5', 'placement': 'san_uri'},
    {'oid': '1.3.6.1.4.1.311.20.2.3', 'label': 'UPN (User Principal Name)', 'asn1_type': 'UTF8', 'placement': 'san_othername'},
    {'oid': '1.2.643.100.3', 'label': 'СНИЛС', 'asn1_type': 'UTF8', 'placement': 'extension'},
    {'oid': '1.2.643.3.131.1.1', 'label': 'ИНН', 'asn1_type': 'UTF8', 'placement': 'extension'},
    {'oid': '1.2.643.100.1', 'label': 'ОГРН', 'asn1_type': 'UTF8', 'placement': 'extension'},
    {'oid': '1.2.643.100.5', 'label': 'ОГРНИП', 'asn1_type': 'UTF8', 'placement': 'extension'},
]


# ── Profile → OID field assignments ──────────────────────────────────────────
# key = profile name; value = [(oid_or_placement_key, required), ...]
# oid_or_placement_key matches OID string or placement for built-in types

PROFILE_OID_ASSIGNMENTS = {
    'server':       [('san_dns', False), ('san_ip', False)],
    'client':       [('san_dns', False), ('san_ip', False)],
    'server_client':[('san_dns', False), ('san_ip', False)],
    'vpn':          [('san_dns', False), ('san_ip', False)],
    'user':         [('1.3.6.1.4.1.311.20.2.3', False), ('san_email', False)],
    'smartcard_logon': [('1.3.6.1.4.1.311.20.2.3', True)],
    'user_login':   [
        ('1.3.6.1.4.1.311.20.2.3', False),
        ('san_email', False),
        ('1.2.643.100.3', False),
    ],
    'smime_sign':   [('san_email', True)],
    'code_signing': [('san_email', False)],
}


def _get_oid_def(OidDef, key):
    if key and '.' in key:
        return OidDef.objects.filter(oid=key).first()
    return OidDef.objects.filter(placement=key, oid='').first()


def seed(apps, schema_editor):
    CertProfile = apps.get_model('dashboard', 'CertProfile')
    OidDef = apps.get_model('dashboard', 'CustomOidDefinition')
    ProfileOidField = apps.get_model('dashboard', 'ProfileOidField')
    CertificateAuthority = apps.get_model('dashboard', 'CertificateAuthority')
    UserProfile = apps.get_model('dashboard', 'UserProfile')
    Group = apps.get_model('auth', 'Group')

    # 1. Seed profiles
    for data in PROFILES:
        CertProfile.objects.get_or_create(name=data['name'], defaults={
            k: v for k, v in data.items() if k != 'name'
        })

    # 2. Seed OID definitions
    for entry in BUILTIN_OIDS:
        OidDef.objects.get_or_create(
            oid=entry['oid'],
            placement=entry['placement'],
            defaults={
                'label': entry['label'],
                'asn1_type': entry['asn1_type'],
                'is_builtin': True,
            },
        )

    # 3. Create ProfileOidField M2M links
    for profile_name, assignments in PROFILE_OID_ASSIGNMENTS.items():
        try:
            profile = CertProfile.objects.get(name=profile_name)
        except CertProfile.DoesNotExist:
            continue
        for idx, (key, required) in enumerate(assignments):
            od = _get_oid_def(OidDef, key)
            if not od:
                continue
            ProfileOidField.objects.get_or_create(
                profile=profile,
                oid_definition=od,
                defaults={'required': required, 'order': idx},
            )

    # 4. Backfill admin assigned CAs (from 0012)
    try:
        admins_group = Group.objects.get(name='admins')
    except Group.DoesNotExist:
        admins_group = None

    if admins_group:
        admin_user_ids = list(admins_group.user_set.values_list('id', flat=True))
        all_cas = list(CertificateAuthority.objects.all())
        if admin_user_ids and all_cas:
            for profile in UserProfile.objects.filter(user_id__in=admin_user_ids):
                profile.assigned_cas.add(*all_cas)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed, noop),
    ]
