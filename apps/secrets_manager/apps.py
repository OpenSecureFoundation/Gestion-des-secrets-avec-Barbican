import logging
import os
import threading
import time

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class SecretsManagerConfig(AppConfig):
    name = 'secrets_manager'

    def ready(self):
        # Django dev server lance ready() deux fois (autoreload).
        # RUN_MAIN='true' identifie le processus enfant (le vrai serveur).
        # En production (gunicorn, uwsgi) RUN_MAIN n'est pas défini → on démarre quand même.
        if os.environ.get('RUN_MAIN') == 'false':
            return

        thread = threading.Thread(
            target=_boucle_renouvellement_auto,
            name='auto-renewal',
            daemon=True,   # s'arrête avec le processus principal
        )
        thread.start()
        logger.info("[AUTO-RENEWAL] Thread de renouvellement automatique démarré.")


# ------------------------------------------------------------------ #
# Boucle de fond : vérifie toutes les AUTO_RENEWAL_INTERVAL secondes #
# ------------------------------------------------------------------ #
def _boucle_renouvellement_auto():
    """
    Thread daemon qui renouvelle automatiquement les secrets dont
    la date d'expiration est dans <= delai_anticipation jours.
    Intervalle configurable via settings.AUTO_RENEWAL_INTERVAL (défaut : 3600 s).
    """
    from django.conf import settings

    # Attendre que Django ait fini son initialisation complète
    time.sleep(15)

    intervalle = getattr(settings, 'AUTO_RENEWAL_INTERVAL', 3600)  # 1 h par défaut

    while True:
        try:
            _executer_renouvellements()
        except Exception as e:
            logger.error(f"[AUTO-RENEWAL] Erreur inattendue dans la boucle : {e}", exc_info=True)
        finally:
            # Fermer les connexions BD ouvertes par ce thread
            from django.db import connection
            connection.close()

        time.sleep(intervalle)


def _executer_renouvellements():
    """
    Requête BD + appel Barbican pour chaque conteneur à renouveler.
    Appelée par la boucle de fond ET réutilisable par la commande `auto_renewal`.
    """
    from django.utils import timezone
    from accounts.views import get_admin_token, token_keystone_scope
    from secrets_manager.fonctions import BarbicanConnectionError, get_barbican_client
    from secrets_manager.models import ConteneurSecret
    from secrets_manager.views import _effectuer_renouvellement

    maintenant = timezone.now()

    conteneurs = (
        ConteneurSecret.objects
        .select_related('projet')
        .prefetch_related('secret')
        .filter(date_expiration__isnull=False, duree_validite__isnull=False)
    )

    for conteneur in conteneurs:
        jours_restants = (conteneur.date_expiration - maintenant).days

        if jours_restants > conteneur.delai_anticipation:
            continue

        nom       = conteneur.nom_conteneur
        projet_id = conteneur.projet.id_projet

        logger.info(
            f"[AUTO-RENEWAL] '{nom}' — {jours_restants} j restants "
            f"(seuil {conteneur.delai_anticipation} j) → renouvellement en cours..."
        )

        try:
            admin_token  = get_admin_token()
            scoped_token = token_keystone_scope(admin_token, projet_id)

            if not scoped_token:
                raise BarbicanConnectionError(
                    f"Token scopé introuvable pour le projet {projet_id}."
                )

            bc          = get_barbican_client(scoped_token, projet_id)
            new_version = _effectuer_renouvellement(bc, conteneur)

            logger.info(
                f"[AUTO-RENEWAL] '{nom}' renouvelé → v{new_version}, "
                f"expiration : {conteneur.date_expiration.date()}"
            )

        except Exception as e:
            logger.error(
                f"[AUTO-RENEWAL] Erreur renouvellement '{nom}' (projet {projet_id}) : {e}",
                exc_info=True,
            )
