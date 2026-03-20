from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class Utilisateur(AbstractUser):
    # On ajoute nos attributs personnalisés
    role = models.CharField(max_length=50, default="creator")
    id_keystone = models.CharField(max_length=255, unique=True, null=True)
    photo_profil = models.ImageField(upload_to='profile_photos/', null=True, blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.username})"
    
