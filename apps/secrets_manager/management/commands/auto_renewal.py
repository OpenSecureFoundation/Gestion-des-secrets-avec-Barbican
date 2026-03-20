"""
Commande Django : force un cycle de renouvellement automatique immédiat.
La même logique tourne aussi en tâche de fond (thread daemon dans apps.py).

Usage :
    python manage.py auto_renewal
"""
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Force un cycle de renouvellement automatique des secrets proches de l'expiration."

    def handle(self, *args, **options):
        from secrets_manager.apps import _executer_renouvellements

        self.stdout.write("Démarrage du cycle de renouvellement...")
        try:
            _executer_renouvellements()
            self.stdout.write(self.style.SUCCESS("Cycle de renouvellement terminé."))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Erreur : {e}"))
