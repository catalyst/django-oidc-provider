# Generated by Django 2.2.9 on 2020-01-28 03:51

from django.db import migrations, models
import oidc_provider.lib.utils.storage


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0028_redirect_uris_help_text'),
    ]

    operations = [
        migrations.AlterField(
            model_name='rsakeyfilesystem',
            name='_key',
            field=models.FileField(help_text='Upload your private key here.', storage=oidc_provider.lib.utils.storage.KeyStorage(), upload_to='', verbose_name='Key'),
        ),
    ]
