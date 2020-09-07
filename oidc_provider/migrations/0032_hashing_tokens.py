
import hashlib

from django.db import migrations


def migrate_hash_existing_tokens(apps, schema_editor):
    for token in apps.get_model('oidc_provider', 'Token').objects.all():
        hasher = hashlib.sha256()
        hasher.update(token.access_token.encode('ascii'))
        token.access_token = hasher.hexdigest()


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0031_refresh_token_expiry'),
    ]

    operations = [
        migrations.RunPython(migrate_hash_existing_tokens),
    ]
