from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secrets_manager', '0005_add_version_fields'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='conteneursecret',
            name='frequence_rotation',
        ),
    ]
