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

from django.test import RequestFactory, TestCase

from dashboard.views import (
    _split_lines,
    _split_san,
    _parse_subject_dn,
    _build_subject,
    _opt_int,
    _unique_name,
)
from dashboard.models import CertProfile


class SplitLinesTest(TestCase):

    def test_empty_string(self):
        self.assertEqual(_split_lines(''), [])

    def test_splits_on_newline(self):
        result = _split_lines('a\nb\nc')
        self.assertEqual(result, ['a', 'b', 'c'])

    def test_strips_blank_lines(self):
        result = _split_lines('a\n\nb')
        self.assertEqual(result, ['a', 'b'])

    def test_strips_whitespace(self):
        result = _split_lines('  hello  \n world ')
        self.assertEqual(result, ['hello', 'world'])


class SplitSanTest(TestCase):

    def test_empty(self):
        self.assertEqual(_split_san(''), [])

    def test_comma_separated(self):
        self.assertIn('a.com', _split_san('a.com, b.com'))
        self.assertIn('b.com', _split_san('a.com, b.com'))

    def test_newline_separated(self):
        self.assertEqual(_split_san('a.com\nb.com'), ['a.com', 'b.com'])


class ParseSubjectDnTest(TestCase):

    def test_parse_full_dn(self):
        result = _parse_subject_dn('/CN=example.com/C=RU/O=Acme/OU=IT/ST=Moscow/L=Moscow')
        self.assertEqual(result['common_name'], 'example.com')
        self.assertEqual(result['country'], 'RU')
        self.assertEqual(result['organization'], 'Acme')

    def test_parse_cn_only(self):
        result = _parse_subject_dn('/CN=only.cn')
        self.assertEqual(result['common_name'], 'only.cn')
        self.assertNotIn('country', result)

    def test_parse_empty(self):
        result = _parse_subject_dn('')
        self.assertEqual(result, {})


class BuildSubjectTest(TestCase):

    def setUp(self):
        self.factory = RequestFactory()

    def test_builds_subject_from_post(self):
        request = self.factory.post('/', {
            'common_name': 'test.example.com',
            'country': 'RU',
            'organization': 'Acme',
        })
        subject = _build_subject('test.example.com', request)
        self.assertIn('/CN=test.example.com', subject)
        self.assertIn('/C=RU', subject)
        self.assertIn('/O=Acme', subject)

    def test_builds_minimal_subject_with_cn_only(self):
        request = self.factory.post('/', {'common_name': 'test.example.com'})
        subject = _build_subject('test.example.com', request)
        self.assertEqual(subject, '/CN=test.example.com')


class OptIntTest(TestCase):
    # _opt_int(post_dict, field_name) → int or None

    def test_valid_int(self):
        self.assertEqual(_opt_int({'days': '42'}, 'days'), 42)

    def test_missing_field_returns_none(self):
        self.assertIsNone(_opt_int({}, 'days'))

    def test_empty_string_returns_none(self):
        self.assertIsNone(_opt_int({'days': ''}, 'days'))

    def test_non_numeric_returns_none(self):
        self.assertIsNone(_opt_int({'days': 'abc'}, 'days'))

    def test_negative_returns_none(self):
        self.assertIsNone(_opt_int({'days': '-5'}, 'days'))


class UniqueNameTest(TestCase):
    # The seed migration already created 'server'. Use a test-specific base.

    def setUp(self):
        CertProfile.objects.create(name='_test_base', display_name='Base')
        CertProfile.objects.create(name='_test_base_copy', display_name='Base Copy')

    def test_generates_unique_name(self):
        result = _unique_name(CertProfile, 'name', '_test_base')
        self.assertFalse(CertProfile.objects.filter(name=result).exists())

    def test_does_not_collide_with_existing(self):
        name1 = _unique_name(CertProfile, 'name', '_test_base')
        CertProfile.objects.create(name=name1, display_name='copy1')
        name2 = _unique_name(CertProfile, 'name', '_test_base')
        self.assertNotEqual(name1, name2)
