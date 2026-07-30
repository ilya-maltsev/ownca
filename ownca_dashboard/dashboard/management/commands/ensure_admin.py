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
from django.contrib.auth.models import User
from django.conf import settings


class Command(BaseCommand):
    help = 'Ensure the single superuser exists (from env vars); remove stale non-superuser accounts'

    def handle(self, *args, **options):
        username = settings.DASHBOARD_ADMIN_USER
        password = settings.DASHBOARD_ADMIN_PASSWORD

        user, created = User.objects.get_or_create(username=username)
        user.set_password(password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        # Remove any other accounts that are not superusers (demo safety net)
        deleted, _ = User.objects.exclude(username=username).filter(is_superuser=False).delete()
        if deleted:
            self.stdout.write(f'Removed {deleted} stale non-superuser account(s).')

        # Ensure UserProfile exists
        from dashboard.models import UserProfile
        UserProfile.objects.get_or_create(user=user)

        if created:
            self.stdout.write(f'Superuser "{username}" created.')
        else:
            self.stdout.write(f'Superuser "{username}" updated.')
