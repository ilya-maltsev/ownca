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

import shutil
import tempfile
import unittest
import uuid

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from dashboard import own_ca
from dashboard.own_ca import CASpec, CertSpec
from dashboard.models import (
    CertProfile, CertificateAuthority, Certificate, UserProfile,
)

GOST_AVAILABLE = own_ca.gost_engine_loaded()


def make_superuser(username='admin', password='testpass') -> User:
    user = User.objects.create_superuser(username=username, password=password)
    UserProfile.objects.get_or_create(user=user)
    return user


def make_cert_profile(**kwargs) -> CertProfile:
    defaults = {
        'name': f'_test_{uuid.uuid4().hex[:8]}',
        'display_name': 'Test Profile',
        'ku_digital_signature': True,
        'eku': 'serverAuth',
    }
    defaults.update(kwargs)
    return CertProfile.objects.create(**defaults)


class DashboardTestCase(TestCase):
    """Base class: creates superuser, logs in the test client."""

    def setUp(self):
        # Use a unique username derived from the test class name to avoid
        # cross-class username conflicts when multiple classes share a DB
        # transaction boundary.
        username = f'test_{self.__class__.__name__.lower()[:20]}'
        self.user = make_superuser(username=username)
        self.client.force_login(self.user)


class CATestCase(DashboardTestCase):
    """Base class for tests that need a real CA on disk.

    Creates the CA in setUp (not setUpClass) to avoid transaction boundary
    and connection-close issues across test classes.
    """

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix='ownca_test_')
        self._override = override_settings(OWNCA_STORAGE_DIR=self._tmp)
        self._override.enable()

        self.ca_uuid = str(uuid.uuid4())
        own_ca.create_root_ca(self.ca_uuid, CASpec(
            name='Test Root CA',
            subject='/CN=Test Root/O=Test',
            key_alg='rsa:2048',
            days=30,
        ))
        self.ca = CertificateAuthority.objects.create(
            uuid=self.ca_uuid,
            name='Test Root CA',
            ca_type='root',
            subject='/CN=Test Root/O=Test',
            key_alg='rsa:2048',
        )
        self.profile = make_cert_profile()

    def tearDown(self):
        if self._override:
            self._override.disable()
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
        super().tearDown()
