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

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from dashboard import own_ca


class Command(BaseCommand):
    help = 'Strip human-readable dump prefix from existing cert.pem / ca.crt files'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Report what would change without touching files.',
        )

    def handle(self, *args, **options):
        dry = options['dry_run']
        root = Path(getattr(settings, 'OWNCA_STORAGE_DIR', '/var/lib/ownca'))
        if not root.exists():
            self.stdout.write(f'storage root {root} does not exist, nothing to do')
            return

        targets = list((root / 'cas').glob('*/ca.crt')) + \
                  list((root / 'certs').glob('*/cert.pem'))

        cleaned = skipped = failed = 0
        for path in targets:
            try:
                raw = path.read_bytes()
            except OSError as e:
                self.stderr.write(f'{path}: read failed ({e})')
                failed += 1
                continue

            # Pure PEM files start with the BEGIN marker (possibly preceded by
            # whitespace only). Anything else means there's a text preamble.
            if raw.lstrip().startswith(b'-----BEGIN '):
                skipped += 1
                continue

            if dry:
                self.stdout.write(f'would clean: {path}')
                cleaned += 1
                continue

            try:
                # `openssl x509 -in F -out F` re-emits just the PEM block.
                own_ca._run(['x509', '-in', str(path), '-out', str(path)])
            except own_ca.OwnCAError as e:
                self.stderr.write(f'{path}: openssl failed ({e})')
                failed += 1
                continue

            self.stdout.write(f'cleaned: {path}')
            cleaned += 1

        summary = f'cleaned={cleaned} skipped={skipped} failed={failed}'
        if dry:
            summary = '[dry-run] ' + summary
        self.stdout.write(summary)
