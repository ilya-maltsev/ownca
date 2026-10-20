from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0004_issuance_mode_toggles'),
    ]

    operations = [
        migrations.CreateModel(
            name='CryptoProSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('license_serial', models.CharField(blank=True, default='', help_text='CryptoPro CSP license serial. Overrides the OWNCA_CRYPTOPRO_LICENSE env value. Blank => env value, then 90-day demo license.', max_length=64)),
                ('license_applied_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'CryptoPro Settings',
                'verbose_name_plural': 'CryptoPro Settings',
            },
        ),
    ]
