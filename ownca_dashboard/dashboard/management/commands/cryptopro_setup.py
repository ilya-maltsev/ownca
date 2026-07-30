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

from django.core.management.base import BaseCommand

from dashboard import cryptopro


class Command(BaseCommand):
    help = (
        'Apply CryptoPro CSP startup configuration (license). No-op when '
        'CryptoPro is not installed in the image. Never fails the boot.'
    )

    def handle(self, *args, **options):
        if not cryptopro.available():
            self.stdout.write('CryptoPro not installed in this image — skipping.')
            return
        serial, source = cryptopro.effective_license_serial()
        if not serial:
            self.stdout.write('CryptoPro license: using built-in demo (no serial set).')
            return
        try:
            cryptopro.apply_license(serial)
            self.stdout.write(self.style.SUCCESS(
                f'CryptoPro license applied from {source}.'))
        except cryptopro.CryptoProError as e:
            # Never fail the boot on a license hiccup — the demo license keeps
            # the CSP usable for 90 days.
            self.stderr.write(f'CryptoPro license not applied ({source}): {e}')
