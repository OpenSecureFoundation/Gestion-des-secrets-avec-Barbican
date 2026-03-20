from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='utilisateur',
            name='photo_profil',
            field=models.ImageField(blank=True, null=True, upload_to='profile_photos/'),
        ),
    ]
