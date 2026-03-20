from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secrets_manager', '0004_add_duree_validite'),
    ]

    operations = [
        migrations.AddField(
            model_name='conteneursecret',
            name='version',
            field=models.IntegerField(default=1, help_text='Version du conteneur, incrémentée à chaque renouvellement'),
        ),
        migrations.AddField(
            model_name='secret',
            name='version',
            field=models.IntegerField(default=1, help_text='Version du secret, correspond à celle du conteneur'),
        ),
    ]
