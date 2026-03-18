from django.db import models

from BarbiLink import settings

# Create your models here.

 # ===== MODELE APPLICATION =====
class Application(models.Model):
    id_app = models.CharField(max_length=255)
    nom_app = models.CharField(max_length=255)
    password_app = models.CharField(max_length=255)
    description_app = models.CharField(max_length=500, blank=True, null=True)
    role = models.CharField(max_length=100, blank=True, null=True)
    date_creation = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.id_app} - {self.nom_app} - {self.password_app} ({self.date_creation})"

    class Meta:
        db_table = 'application'


# ===== MODELE PROJET =====
class Projet(models.Model):
    id_projet = models.CharField(max_length=255, unique=True)
    nom_projet = models.CharField(max_length=255)

    # Clé étrangère vers Application — suppression projet → suppression application
    application = models.OneToOneField(
        Application,
        on_delete=models.CASCADE,  # supprime l'application si le projet est supprimé
        related_name='projet',
        null=True,
        blank=True
    )

    # Relation vers Utilisateur
    utilisateur = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='projets'
    )

    def __str__(self):
        return f"{self.id_projet} - {self.nom_projet}"

    class Meta:
        db_table = 'projet'
