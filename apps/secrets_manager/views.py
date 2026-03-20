from datetime import timedelta
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse
from django.utils import timezone
import logging

from BarbiLink import settings
from accounts.views import token_keystone_scope
from apps_manager.models import Projet
from secrets_manager.fonctions import (
    BarbicanConnectionError, BarbicanContainerError, BarbicanOrderError,
    BarbicanTimeoutError, CAInfrastructureError, CASigningError, CSRGenerationError,
    generer_cle_asymetrique, generer_ssl,
    get_barbican_client, stocker_cle_barbican, stocker_cle_unique_conteneur_barbican,
    supprimer_conteneur_barbican, supprimer_secret_barbican,
)
from secrets_manager.models import ConteneurSecret, Secret
from secrets_manager.utils import _traiter_certificat_ssl, _traiter_cle, generer_cle_symetrique
from .forms import AjouterSecretForm
from api_manager.notifications import notifier_secret_cree, notifier_secret_renouvele

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------- #
# FONCTION POUR AJOUTER UN SECRET A UNE NOUVELLE APPLICATION            #
# --------------------------------------------------------------------- #
@login_required
def ajouter_secret_view(request):
    template         = "secrets_manager/creer_secret.html"
    template_partiel = "secrets_manager/creer_secret_partiel.html"

    projet_id = request.GET.get("projet_id") or request.POST.get("projet_id")
    request.session.pop("nouveau_app_nom", None)


    if request.method == "POST":
        form = AjouterSecretForm(request.POST, request.FILES)
        if form.is_valid():
            nom_secret_saisi = form.cleaned_data.get("nom_secret")
            # Vérification d'unicité du nom de secret pour ce projet
            if ConteneurSecret.objects.filter(projet__id_projet=projet_id, nom_conteneur=nom_secret_saisi).exists():
                return render(request, template_partiel, {
                    "form":      form,
                    "form_data": request.POST,
                    "projet_id": projet_id,
                    "error":     f"Un secret nommé « {nom_secret_saisi} » existe déjà pour cette application. Choisissez un autre nom.",
                })

            type_secret  = form.cleaned_data.get("type_secret")
            token_actuel = request.session.get("keystone_token")
            scoped_token = token_keystone_scope(token_actuel, projet_id)
            bc           = get_barbican_client(scoped_token, projet_id)

            données_cle = {
                "api_type":             form.cleaned_data.get("api_type"),
                "api_action":           form.cleaned_data.get("api_action"),
                "secret_name":          form.cleaned_data.get("nom_secret"),
                "duree_validite":       form.cleaned_data.get("duree_validite"),
                "delai_renouvellement": form.cleaned_data.get("delai_renouvellement"),
                "id_projet":            projet_id,
                "api_key_file":         form.cleaned_data["api_key_file"].read().decode("utf-8")
                                        if form.cleaned_data.get("api_key_file") else None,
                "api_private_key_file": form.cleaned_data["api_private_key_file"].read().decode("utf-8")
                                        if form.cleaned_data.get("api_private_key_file") else None,
                "api_public_key_file":  form.cleaned_data["api_public_key_file"].read().decode("utf-8")
                                        if form.cleaned_data.get("api_public_key_file") else None,
            }

            données_ssl = {
                "secret_name":          form.cleaned_data.get("nom_secret"),
                "ssl_action":           form.cleaned_data.get("ssl_action"),
                "duree_validite":       form.cleaned_data.get("duree_validite"),
                "delai_renouvellement": form.cleaned_data.get("delai_renouvellement"),
                "id_projet":            projet_id,
                "ssl_cert_file":        form.cleaned_data["ssl_cert_file"].read().decode("utf-8")
                                        if form.cleaned_data.get("ssl_cert_file") else None,
                "ssl_key_file":         form.cleaned_data["ssl_key_file"].read().decode("utf-8")
                                        if form.cleaned_data.get("ssl_key_file") else None,
                "ssl_domaine":          form.cleaned_data.get("ssl_domaine"),
                "ssl_organisation":     form.cleaned_data.get("ssl_organisation"),
                "ssl_pays":             form.cleaned_data.get("ssl_pays"),
                "ssl_region":           form.cleaned_data.get("ssl_region"),
                "ssl_ville":            form.cleaned_data.get("ssl_ville"),
            }

            # ── Helper pour logger + print + render ── #
            def gerer_erreur(message_utilisateur, message_technique, exception=None):
                if exception:
                    logger.error(f"{message_technique} : {str(exception)}", exc_info=True)
                else:
                    logger.error(message_technique)
                return render(request, template_partiel, {
                    "form":      form,
                    "form_data": request.POST,
                    "projet_id": projet_id,
                    "error":     message_utilisateur,
                })

            # ── Traitement selon le type de secret ── #
            try:
                if type_secret == "api":
                    resultat = _traiter_cle(bc, données_cle)
                elif type_secret == "ssl":
                    resultat = _traiter_certificat_ssl(bc, données_ssl)
                else:
                    return gerer_erreur(
                        "Type de secret non reconnu.",
                        f"Type de secret invalide reçu : '{type_secret}'",
                    )

                _sauvegarder_en_base(
                    données=données_cle if type_secret == "api" else données_ssl,
                    resultat=resultat,
                    project_id=projet_id,
                )
                nom_secret = form.cleaned_data.get('nom_secret')
                logger.info("Secret '%s' ajouté pour le projet %s.", nom_secret, projet_id)
                nom_app = request.session.pop("nouveau_app_nom", None)
                if not nom_app:
                    try:
                        p = Projet.objects.select_related('application').get(id_projet=projet_id)
                        nom_app = p.application.nom_app if p.application else projet_id
                    except Projet.DoesNotExist:
                        nom_app = projet_id
                notifier_secret_cree(request.user, nom_secret, nom_app)
                if nom_app:
                    messages.success(request, f"Application « {nom_app} » et secret « {nom_secret} » créés avec succès.")
                else:
                    messages.success(request, f"Secret « {nom_secret} » ajouté avec succès.")
                return redirect("apps_manager:list_app")

            except BarbicanConnectionError as e:
                return gerer_erreur(
                    "Impossible de joindre Barbican. Réessayez plus tard.",
                    "Erreur de connexion à Barbican",
                    e,
                )
            except BarbicanOrderError as e:
                return gerer_erreur(
                    "Barbican a échoué à générer le secret. Réessayez plus tard.",
                    "Erreur lors de la génération de l'ordre Barbican",
                    e,
                )
            except BarbicanTimeoutError as e:
                return gerer_erreur(
                    "Barbican met trop de temps à répondre. Réessayez plus tard.",
                    "Timeout lors du polling de l'ordre Barbican",
                    e,
                )
            except BarbicanContainerError as e:
                return gerer_erreur(
                    "Erreur lors de la récupération des clés. Réessayez plus tard.",
                    "Erreur d'accès au conteneur Barbican",
                    e,
                )
            except CSRGenerationError as e:
                return gerer_erreur(
                    "Échec de la génération de la CSR. Réessayez plus tard.",
                    "Erreur lors de la génération de la CSR",
                    e,
                )
            except CAInfrastructureError as e:
                return gerer_erreur(
                    "Fichiers CA introuvables. Contactez un administrateur.",
                    "Erreur d'infrastructure CA (fichiers manquants ou corrompus)",
                    e,
                )
            except CASigningError as e:
                return gerer_erreur(
                    "Échec de la signature du certificat. Réessayez plus tard.",
                    "Erreur lors de la signature du certificat par la CA",
                    e,
                )

        # Formulaire invalide
        logger.warning(f"Formulaire d'ajout de secret invalide : {form.errors}")
        return render(request, template_partiel, {
            "form":      form,
            "form_data": request.POST,
            "projet_id": projet_id,
            "error":     "Formulaire invalide. Vérifiez les champs et réessayez.",
        })

    # ── GET ── #
    else:
        form = AjouterSecretForm()
        return render(request, template, {
            "form":      form,
            "form_data": {},
            "projet_id": projet_id,
        })


# --------------------------------------------------------------------- #
# FONCTION POUR PROPOSER L'AJOUT D'UN SECRET A UNE NOUVELLE APPLICATION #
# --------------------------------------------------------------------- #
@login_required
def proposition_secret_view(request):
    
    app_nom = request.session.get("nouveau_app_nom")
    projet_id = request.session.get('projet_id_actuel')

    if not app_nom:
        # Accès direct sans création préalable → redirection
        return redirect("apps_manager:list_app")

    # Récupération du projet depuis la base via le nom
    try:
        projet = Projet.objects.get(
            nom_projet=f"projet_{app_nom}",
            utilisateur=request.user,
        )
    except Projet.DoesNotExist:
        return redirect("apps_manager:list_app")

    return render(request, "secrets_manager/proposition_secret.html", {
        "projet_id":  projet_id,
        "app_nom": app_nom,
    })


# --------------------------------------------------------------------- #
# FONCTION POUR ANNULER L'AJOUT D'UN SECRET A UNE NOUVELLE APPLICATION  #
# --------------------------------------------------------------------- #
@login_required
def passer_secret_view(request):
    nom_app = request.session.pop("nouveau_app_nom", None)
    if nom_app:
        messages.success(request, f"Application « {nom_app} » créée avec succès.")
    if request.headers.get("HX-Request"):
        response = HttpResponse()
        response["HX-Redirect"] = reverse("apps_manager:list_app")
        return response
    return redirect("apps_manager:list_app")




# ------------------------------------------------------------------------ #
# FONCTION POUR SAUVEGARDER LE NOUVEAU CONTENEUR ET SON(SES) SECRETS EN BD #
# ------------------------------------------------------------------------ #
def _sauvegarder_en_base(données, resultat, project_id):

    try:
        projet = Projet.objects.get(id_projet=project_id)
    except Projet.DoesNotExist:
        logger.error(f"Projet introuvable : {project_id}")
        raise

    try:
        # 1. On cherche d'abord si un conteneur avec ce nom existe déjà pour ce projet
        conteneur = ConteneurSecret.objects.filter(
            projet=projet, 
            nom_conteneur=données["secret_name"]
        ).first()

        if conteneur:
            # --- LOGIQUE DE BASCULE DEMANDÉE ---
            # Si ref_old_conteneur a déjà une valeur (n'est pas vide)
            if conteneur.ref_old_conteneur:
                # On stocke la nouvelle référence dans ref_new_conteneur
                conteneur.ref_new_conteneur = resultat["container_ref"]
            else:
                # Sinon, on la garde dans ref_old_conteneur
                conteneur.ref_old_conteneur = resultat["container_ref"]
            
            # Mise à jour des autres infos (dates, domaines, etc.)
            conteneur.type_conteneur = resultat["type_conteneur"]
            conteneur.duree_validite = données["duree_validite"]
            conteneur.date_expiration = timezone.now() + timedelta(days=données["duree_validite"])
            conteneur.delai_anticipation = données["delai_renouvellement"]
            conteneur.domaine_app = données.get("ssl_domaine")
            
            conteneur.save()
        else:
            # --- CRÉATION INITIALE ---
            # Si c'est la toute première fois, on crée l'objet normalement
            conteneur = ConteneurSecret.objects.create(
                projet=projet,
                nom_conteneur=données["secret_name"],
                type_conteneur=resultat["type_conteneur"],
                ref_old_conteneur=resultat["container_ref"],
                duree_validite=données["duree_validite"],
                date_expiration=timezone.now() + timedelta(days=données["duree_validite"]),
                delai_anticipation=données["delai_renouvellement"],
                domaine_app=données.get("ssl_domaine"),
            )
        logger.info(f"ConteneurSecret '{conteneur.nom_conteneur}' créé.")
    except Exception as e:
        logger.error(f"Erreur création ConteneurSecret : {str(e)}", exc_info=True)
        raise

    try:
        for secret_data in resultat["secrets"]:
            Secret.objects.create(
                conteneur=conteneur,
                nom_secret=secret_data["nom"],
                type_secret=secret_data["type_secret"],
                ref_secret=secret_data["ref"],
            )
            logger.info(f"Secret '{secret_data['nom']}' créé.")
    except Exception as e:
        logger.error(f"Erreur création secrets : {str(e)}", exc_info=True)
        conteneur.delete()
        logger.warning(f"Rollback : ConteneurSecret '{conteneur.nom_conteneur}' supprimé.")
        raise


# --------------------------------------------------------------------- #
# HELPER : LOGIQUE DE RENOUVELLEMENT (réutilisable par la vue et la    #
# commande de renouvellement automatique)                               #
# --------------------------------------------------------------------- #
def _effectuer_renouvellement(bc, conteneur):
    """
    Crée de nouveaux secrets/conteneur dans Barbican et met à jour la BD.

    Rotation des refs (sans supprimer le conteneur actif) :
      - 1er renouvellement (ref_new vide) :
            ref_old_conteneur  inchangé  (conteneur original conservé)
            ref_new_conteneur  ← nouveau conteneur
      - Renouvellements suivants (ref_new déjà occupé) :
            ref_old_conteneur  ← ancien ref_new  (conteneur précédent conservé)
            ref_new_conteneur  ← nouveau conteneur
            (l'ancien ref_old est supprimé de Barbican car le plus ancien)
    """
    new_version   = conteneur.version + 1
    nom           = conteneur.nom_conteneur
    versioned_nom = f"{nom}_v{new_version}"
    type_c        = conteneur.type_conteneur

    # ── 1. Créer les nouveaux secrets/conteneurs selon le type ── #
    if type_c == 'generic':
        new_secret_ref    = generer_cle_symetrique(bc, versioned_nom)
        new_container_ref = stocker_cle_unique_conteneur_barbican(bc, versioned_nom, new_secret_ref)
        nouveaux_secrets  = [
            {'nom': nom, 'type_secret': 'symmetric', 'ref': new_secret_ref},
        ]

    elif type_c == 'rsa':
        new_container_ref = generer_cle_asymetrique(bc, versioned_nom)
        rsa_container     = bc.containers.get(new_container_ref)
        nouveaux_secrets  = [
            {'nom': f"{nom}-private", 'type_secret': 'asymmetric',
             'ref': rsa_container.secrets.get('private_key').secret_ref},
            {'nom': f"{nom}-public",  'type_secret': 'asymmetric',
             'ref': rsa_container.secrets.get('public_key').secret_ref},
        ]

    elif type_c == 'certificate':
        new_container_ref = generer_ssl(bc, {
            'secret_name':      versioned_nom,
            'duree_validite':   conteneur.duree_validite,
            'ssl_domaine':      conteneur.domaine_app or '',
            'ssl_organisation': '',
            'ssl_pays':         '',
            'ssl_region':       '',
            'ssl_ville':        '',
        })
        tls_container    = bc.containers.get(new_container_ref)
        nouveaux_secrets = [
            {'nom': f"{nom}-certificate", 'type_secret': 'certificate',
             'ref': tls_container.secrets.get('certificate').secret_ref},
            {'nom': f"{nom}-private",     'type_secret': 'asymmetric',
             'ref': tls_container.secrets.get('private_key').secret_ref},
        ]

    else:
        raise BarbicanConnectionError(f"Type de conteneur inconnu : '{type_c}'")

    # ── 2. Rotation des refs sans supprimer le conteneur actif ── #
    if conteneur.ref_new_conteneur:
        # ref_new est déjà occupé : déplacer ref_new → ref_old
        # L'ancien ref_old (le plus vieux) est supprimé de Barbican
        if conteneur.ref_old_conteneur:
            supprimer_conteneur_barbican(bc, conteneur.ref_old_conteneur)
        conteneur.ref_old_conteneur = conteneur.ref_new_conteneur
        conteneur.ref_new_conteneur = new_container_ref
    else:
        # Premier renouvellement : ref_old garde l'original, ref_new reçoit le nouveau
        conteneur.ref_new_conteneur = new_container_ref

    # ── 3. Mettre à jour la base de données ── #
    conteneur.secret.all().delete()
    for s_data in nouveaux_secrets:
        Secret.objects.create(
            conteneur=conteneur,
            nom_secret=s_data['nom'],
            type_secret=s_data['type_secret'],
            ref_secret=s_data['ref'],
            version=new_version,
        )
    conteneur.version         = new_version
    conteneur.date_expiration = timezone.now() + timedelta(days=conteneur.duree_validite)
    conteneur.save()

    logger.info(
        f"[RENOUVELLEMENT] '{nom}' v{new_version} — "
        f"ref_old={conteneur.ref_old_conteneur} | ref_new={conteneur.ref_new_conteneur}"
    )
    return new_version


# --------------------------------------------------------------------- #
# VUE : RENOUVELLEMENT MANUEL (bouton sync dans la liste)               #
# --------------------------------------------------------------------- #
@login_required
def renouveler_secret_view(request):
    if request.method != 'POST':
        return redirect('apps_manager:list_app')

    conteneur_id = request.POST.get('conteneur_id')
    conteneur    = get_object_or_404(ConteneurSecret, id=conteneur_id, projet__utilisateur=request.user)
    projet_id    = conteneur.projet.id_projet

    redirect_to = request.POST.get('redirect_to', 'list')

    def _redirect_response(projet_id):
        response = HttpResponse()
        if redirect_to == 'detail':
            response['HX-Redirect'] = reverse('apps_manager:detail_app') + f'?projet_id={projet_id}'
        else:
            response['HX-Redirect'] = reverse('apps_manager:list_app')
        return response

    if not conteneur.duree_validite:
        messages.error(request, "Durée de validité non définie. Modifiez l'application d'abord.")
        return _redirect_response(projet_id)

    user_token = token_keystone_scope(request.session.get('keystone_token'), projet_id)
    if not user_token:
        messages.error(request, "Session expirée. Veuillez vous reconnecter.")
        return _redirect_response(projet_id)

    try:
        bc          = get_barbican_client(user_token, projet_id)
        new_version = _effectuer_renouvellement(bc, conteneur)
        notifier_secret_renouvele(
            request.user,
            conteneur.nom_conteneur,
            conteneur.projet.application.nom_app if conteneur.projet.application else conteneur.projet.nom_projet,
            mode="manuel",
        )
        messages.success(request, f"Secret « {conteneur.nom_conteneur} » renouvelé avec succès (version {new_version}).")
    except Exception as e:
        logger.error(f"Erreur renouvellement secret '{conteneur_id}' : {str(e)}", exc_info=True)
        messages.error(request, f"Erreur lors du renouvellement : {str(e)}")

    return _redirect_response(projet_id)