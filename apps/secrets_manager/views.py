from datetime import timedelta, timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from BarbiLink import settings
from accounts.views import token_keystone_scope
from apps_manager.models import Projet
from secrets_manager.fonctions import BarbicanConnectionError, BarbicanContainerError, BarbicanOrderError, BarbicanTimeoutError, CAInfrastructureError, CASigningError, CSRGenerationError, get_barbican_client
from secrets_manager.models import ConteneurSecret, Secret
from secrets_manager.utils import _traiter_certificat_ssl, _traiter_cle, generer_cle_asymetrique, generer_cle_symetrique
from .forms import AjouterSecretForm
import logging

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------- #
# FONCTION POUR AJOUTER UN SECRET A UNE NOUVELLE APPLICATION            #
# --------------------------------------------------------------------- #
def ajouter_secret_view(request):
    template         = "secrets_manager/creer_secret.html"
    template_partiel = "secrets_manager/creer_secret_partiel.html"

    projet_id = request.GET.get("projet_id") or request.POST.get("id_projet")
    request.session.pop("nouveau_app_nom", None)

    if request.method == "POST":
        form = AjouterSecretForm(request.POST, request.FILES)
        if form.is_valid():
            type_secret  = form.cleaned_data.get("type_secret")
            token_actuel = request.session.get("keystone_token")
            scoped_token = token_keystone_scope(token_actuel, projet_id)
            bc           = get_barbican_client(scoped_token)

            données_cle = {
                "api_type":             form.cleaned_data.get("api_type"),
                "api_action":           form.cleaned_data.get("api_action"),
                "secret_name":          form.cleaned_data.get("nom_secret"),
                "duree_validite":       form.cleaned_data.get("duree_validite"),
                "frequence_rotation":   form.cleaned_data.get("frequence_rotation"),
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
                "frequence_rotation":   form.cleaned_data.get("frequence_rotation"),
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
                print(f"[ERREUR] {message_technique}")
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
                    resultat = _traiter_cle(bc, scoped_token, données_cle)
                elif type_secret == "ssl":
                    resultat = _traiter_certificat_ssl(bc, scoped_token, données_ssl)
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
                print("[SUCCÈS] Secret ajouté avec succès !")
                logger.info(f"Secret '{form.cleaned_data.get('nom_secret')}' ajouté avec succès pour le projet {projet_id}.")
                messages.success(request, "Secret ajouté avec succès !")
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
        print("[ERREUR] Formulaire invalide.")
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
def proposition_secret_view(request):
    
    app_nom = request.session.get("nouveau_app_nom")

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
        "projet_id":  projet.id_projet,
        "app_nom": app_nom,
    })


# --------------------------------------------------------------------- #
# FONCTION POUR ANNULER L'AJOUT D'UN SECRET A UNE NOUVELLE APPLICATION  #
# --------------------------------------------------------------------- #
def passer_secret_view(request):
    
    request.session.pop("nouveau_app_nom", None)
    return redirect("apps_manager:list_app")




# ------------------------------------------------------------------------ #
# FONCTION POUR SAUVEGARDER LE NOUVEAU CONTENEUR ET SON(SES) SECRETS EN BD #
# ------------------------------------------------------------------------ #
def _sauvegarder_en_base(données, resultat, project_id):

    try:
        projet = Projet.objects.get(id_projet=project_id)
    except Projet.DoesNotExist:
        logger.error(f"Projet introuvable : {project_id}")
        print(f"[ERREUR] Projet introuvable : {project_id}")
        raise

    try:
        conteneur = ConteneurSecret.objects.create(
            projet=projet,
            nom_conteneur=données["secret_name"],
            type_conteneur=resultat["type_conteneur"],
            ref_old_conteneur=resultat["container_ref"],
            date_expiration=timezone.now() + timedelta(days=données["duree_validite"]),
            frequence_rotation=données["frequence_rotation"],
            delai_anticipation=données["delai_renouvellement"],
            domaine_app=données.get("ssl_domaine"),
        )
        logger.info(f"ConteneurSecret '{conteneur.nom_conteneur}' créé.")
        print(f"[SUCCÈS] ConteneurSecret '{conteneur.nom_conteneur}' créé.")
    except Exception as e:
        logger.error(f"Erreur création ConteneurSecret : {str(e)}", exc_info=True)
        print(f"[ERREUR] Erreur création ConteneurSecret : {str(e)}")
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
            print(f"[SUCCÈS] Secret '{secret_data['nom']}' créé.")
    except Exception as e:
        logger.error(f"Erreur création secrets : {str(e)}", exc_info=True)
        print(f"[ERREUR] Erreur création secrets : {str(e)}")
        conteneur.delete()
        logger.warning(f"Rollback : ConteneurSecret '{conteneur.nom_conteneur}' supprimé.")
        print(f"[ROLLBACK] ConteneurSecret '{conteneur.nom_conteneur}' supprimé.")
        raise