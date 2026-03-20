from django.db import models
from apps_manager.models import Projet  # Import du modèle Projet de l'autre app
from django.utils import timezone


# Create your models here.

class ConteneurSecret(models.Model):
    """
    Modèle central pour le conteneur (Barbican Container)
    """
    
    # --- Identité ---
    projet = models.ForeignKey(Projet, on_delete=models.CASCADE, related_name='conteneur')
    nom_conteneur = models.CharField(max_length=255)
    ref_old_conteneur = models.CharField(max_length=255, unique=True, null=True, help_text="UUID ou URI Barbican")
    ref_new_conteneur = models.CharField(max_length=255, unique=True, null=True, blank=True, help_text="UUID ou URI Barbican")
    type_conteneur = models.CharField(max_length=100) #generic=>cle API simple, RSA=>paire de cles et certificat
    
    # --- Logique de Dates ---
    derniere_modification = models.DateTimeField(auto_now=True)
    date_expiration = models.DateTimeField()
    
    # --- Champs de Configuration du renouvellement ---
    version = models.IntegerField(default=1, help_text="Version du conteneur, incrémentée à chaque renouvellement")
    duree_validite = models.IntegerField(null=True, blank=True, help_text="Durée de validité en jours")
    delai_anticipation = models.IntegerField(default=7, help_text="Alerte X jours avant")

    # --- Champs spécifiques Certificats ---
    domaine_app = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.nom_conteneur
    
class Secret(models.Model):
    """
    Éléments individuels à l'intérieur d'un conteneur
    """
    # Lien FK vers ConteneurSecret
    conteneur = models.ForeignKey(ConteneurSecret, on_delete=models.CASCADE, related_name='secret')
    
    nom_secret = models.CharField(max_length=255)
    type_secret = models.CharField(max_length=100)  # symmetric=>cle API simple, asymmetric=>cle privee/publique, certificat=>certificat (partie publique signee)
    ref_secret = models.CharField(max_length=255, unique=True, help_text="UUID ou URI Barbican")
    version = models.IntegerField(default=1, help_text="Version du secret, correspond à celle du conteneur")

    def __str__(self):
        return f"{self.nom_secret} ({self.type_secret})"

