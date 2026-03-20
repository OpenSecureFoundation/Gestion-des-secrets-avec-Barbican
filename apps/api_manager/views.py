"""
Vues pour l'API BarbiLink :
  - Génération / renouvellement du jeton d'accès (interface utilisateur)
  - Endpoints REST tiers : GET secret, (extension future : POST)
"""
import base64
import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from accounts.views import token_verification, token_keystone_scope
from api_manager.models import TokenAcces
from api_manager.notifications import (
    notifier_token_genere,
    notifier_token_renouvele,
    notifier_acces_api,
)
from secrets_manager.fonctions import get_barbican_client, BarbicanConnectionError
from secrets_manager.models import ConteneurSecret, Secret

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# GÉNÉRATION / RENOUVELLEMENT DU JETON (vues protégées par login)
# ─────────────────────────────────────────────────────────────────────────────

@login_required
@require_POST
def generer_token_view(request):
    """
    Génère (ou crée) un jeton d'accès pour un conteneur donné.
    Appelé via HTMX depuis la carte du secret dans detail_app_content.html.
    """
    conteneur_id = request.POST.get('conteneur_id')
    conteneur = get_object_or_404(
        ConteneurSecret,
        id=conteneur_id,
        projet__utilisateur=request.user,
    )

    token_obj = TokenAcces.generer(conteneur)
    notifier_token_genere(request.user, conteneur.nom_conteneur)
    logger.info("Token généré pour conteneur %s par %s", conteneur.nom_conteneur, request.user.username)

    return JsonResponse({'token': token_obj.token, 'conteneur_id': conteneur_id})


@login_required
@require_POST
def renouveler_token_view(request):
    """
    Renouvelle le jeton existant (révoque l'ancien, génère un nouveau).
    Appelé via HTMX depuis la carte du secret.
    """
    conteneur_id = request.POST.get('conteneur_id')
    conteneur = get_object_or_404(
        ConteneurSecret,
        id=conteneur_id,
        projet__utilisateur=request.user,
    )

    token_obj = TokenAcces.generer(conteneur)
    notifier_token_renouvele(request.user, conteneur.nom_conteneur)
    logger.info("Token renouvelé pour conteneur %s par %s", conteneur.nom_conteneur, request.user.username)

    return JsonResponse({'token': token_obj.token, 'conteneur_id': conteneur_id})


# ─────────────────────────────────────────────────────────────────────────────
# API TIERCE : LECTURE D'UN SECRET
# ─────────────────────────────────────────────────────────────────────────────

def _get_admin_barbican_client(projet_id):
    """Obtient un client Barbican via les credentials admin du service."""
    admin_token = token_verification(
        settings.KEYSTONE_ADMIN_USERNAME,
        settings.KEYSTONE_ADMIN_PASSWORD,
    )
    if not admin_token:
        raise BarbicanConnectionError("Impossible d'obtenir le token admin Keystone.")
    scoped = token_keystone_scope(admin_token, projet_id)
    return get_barbican_client(scoped, projet_id)


def _valider_token_bearer(request):
    """
    Extrait et valide le jeton Bearer.
    Retourne (token_obj, None) ou (None, JsonResponse erreur).
    """
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None, JsonResponse(
            {'erreur': 'Authentification requise. Fournissez un header Authorization: Bearer <jeton>.'},
            status=401,
        )
    token_value = auth_header[7:].strip()
    try:
        token_obj = TokenAcces.objects.select_related(
            'conteneur__projet__utilisateur',
            'conteneur__projet__application',
        ).get(token=token_value)
    except TokenAcces.DoesNotExist:
        return None, JsonResponse(
            {'erreur': 'Jeton invalide ou révoqué. Contactez le propriétaire de l\'application pour obtenir un nouveau jeton.'},
            status=401,
        )
    return token_obj, None


@csrf_exempt
def api_lire_secret_view(request, nom_secret):
    """
    GET /api/v1/secrets/<nom_secret>/
    Headers : Authorization: Bearer <jeton>
    Query param optionnel : ?type=private|public  (uniquement pour RSA)

    Retourne directement la valeur du secret depuis Barbican.
    Rien n'est stocké côté serveur.
    """
    if request.method != 'GET':
        return JsonResponse({'erreur': 'Méthode non autorisée.'}, status=405)

    token_obj, err = _valider_token_bearer(request)
    if err:
        return err

    conteneur = token_obj.conteneur

    # Vérification que le jeton donne accès à CE secret
    if conteneur.nom_conteneur != nom_secret:
        return JsonResponse(
            {'erreur': f'Ce jeton ne vous autorise pas à accéder au secret « {nom_secret} ».'},
            status=403,
        )

    projet = conteneur.projet
    utilisateur = projet.utilisateur
    ip_tierce = request.META.get('REMOTE_ADDR')

    try:
        bc = _get_admin_barbican_client(projet.id_projet)
    except BarbicanConnectionError as e:
        logger.error("API lire_secret: connexion Barbican échouée — %s", e)
        return JsonResponse({'erreur': 'Service temporairement indisponible.'}, status=503)

    try:
        resultat = _lire_valeur_barbican(bc, conteneur, request.GET.get('type', 'public'))
    except Exception as e:
        logger.error("API lire_secret: lecture Barbican échouée — %s", e)
        return JsonResponse({'erreur': 'Impossible de lire le secret.'}, status=500)

    # Notification asynchrone (non bloquante)
    notifier_acces_api(utilisateur, nom_secret, operation="read", ip_tierce=ip_tierce)
    logger.info("Accès API secret '%s' par tiers %s", nom_secret, ip_tierce)

    return JsonResponse(resultat)


def _decoder_payload(payload):
    """
    Tente de décoder le payload en UTF-8.
    Si le contenu est binaire (ex: fichier de clé uploadé), retourne
    une chaîne base64 avec encodage='base64' pour que le client sache.
    """
    if not isinstance(payload, bytes):
        return str(payload), 'text'
    try:
        return payload.decode('utf-8'), 'text'
    except UnicodeDecodeError:
        return base64.b64encode(payload).decode('ascii'), 'base64'


def _lire_valeur_barbican(bc, conteneur, key_type):
    """
    Lit le payload depuis Barbican selon le type de conteneur.
    Retourne un dict JSON-serialisable.
    """
    type_conteneur = conteneur.type_conteneur

    if type_conteneur == 'generic':
        secret_db = conteneur.secret.first()
        if not secret_db:
            raise ValueError("Aucun secret trouvé pour ce conteneur générique.")
        secret_barb = bc.secrets.get(secret_db.ref_secret)
        valeur, encodage = _decoder_payload(secret_barb.payload)
        return {
            'nom': conteneur.nom_conteneur,
            'type': 'generic',
            'valeur': valeur,
            'encodage': encodage,
        }

    elif type_conteneur == 'certificate':
        secret_db = conteneur.secret.filter(type_secret='certificate').first()
        if not secret_db:
            raise ValueError("Certificat introuvable dans ce conteneur.")
        secret_barb = bc.secrets.get(secret_db.ref_secret)
        valeur, encodage = _decoder_payload(secret_barb.payload)
        return {
            'nom': conteneur.nom_conteneur,
            'type': 'certificate',
            'valeur': valeur,
            'encodage': encodage,
        }

    elif type_conteneur == 'rsa':
        if key_type not in ('private', 'public'):
            raise ValueError("Paramètre 'type' invalide. Utilisez 'private' ou 'public'.")
        type_secret_cible = 'private' if key_type == 'private' else 'public'
        secret_db = conteneur.secret.filter(type_secret__icontains=type_secret_cible).first()
        if not secret_db:
            raise ValueError(f"Clé {key_type} introuvable dans ce conteneur RSA.")
        secret_barb = bc.secrets.get(secret_db.ref_secret)
        valeur, encodage = _decoder_payload(secret_barb.payload)
        return {
            'nom': conteneur.nom_conteneur,
            'type': f'rsa_{key_type}',
            'valeur': valeur,
            'encodage': encodage,
        }

    else:
        raise ValueError(f"Type de conteneur non supporté : {type_conteneur}")
