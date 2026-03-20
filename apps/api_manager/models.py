import secrets as secrets_module

from django.db import models
from django.conf import settings


class TokenAcces(models.Model):
    """
    Jeton d'accès permettant à une application tierce de lire un secret via l'API.
    Un jeton par conteneur de secret (OneToOne).
    """
    conteneur = models.OneToOneField(
        'secrets_manager.ConteneurSecret',
        on_delete=models.CASCADE,
        related_name='token_acces',
    )
    token = models.CharField(max_length=64, unique=True)
    cree_le = models.DateTimeField(auto_now_add=True)
    renouvele_le = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Token[{self.conteneur.nom_conteneur}]"

    @classmethod
    def generer(cls, conteneur):
        """Crée ou renouvelle le jeton pour un conteneur donné."""
        nouveau_token = secrets_module.token_hex(32)   # 64 chars hex
        obj, _ = cls.objects.get_or_create(conteneur=conteneur)
        obj.token = nouveau_token
        obj.save()
        return obj
