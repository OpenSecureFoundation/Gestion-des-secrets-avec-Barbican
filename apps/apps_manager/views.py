import logging
import re
from datetime import date as date_type, timedelta
from django.core.paginator import Paginator

from django.contrib import messages
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
import requests
from django.conf import settings
from accounts.views import get_admin_token, get_user_barbican_id, get_user_keystone_id, token_keystone_scope
from apps_manager.models import Application, Projet
from django.contrib.auth.decorators import login_required
from secrets_manager.fonctions import (
    BarbicanConnectionError,
    get_barbican_client,
    renommer_secrets_conteneur_barbican,
    supprimer_conteneur_barbican,
    supprimer_secret_barbican,
)
from secrets_manager.models import ConteneurSecret, Secret
from api_manager.models import TokenAcces
from api_manager.notifications import (
    notifier_app_creee,
    notifier_app_modifiee,
    notifier_app_supprimee,
    notifier_apps_supprimees_masse,
    notifier_secret_supprime,
    notifier_secret_modifie,
    notifier_secrets_supprimes_masse,
)

logger = logging.getLogger(__name__)

# Create your views here.


#------------------------------- FONCTIONS DE CREATION ----------------------------------#

# Fonction pour creer un projet dans keystone
def creer_keystone_projet(admin_token, name_projet, description, user_id, admin_id, barbican_id, role):
    url = f"{settings.KEYSTONE_URL}/projects"
    headers = {"X-Auth-Token": admin_token, "Content-Type": "application/json"}
    payload = {
        "project": {
            "name": name_projet,
            "description": description,
            "enabled": True
        }
    }
    try:
        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 201:
            project_data = response.json()['project']
            project_id = project_data['id']
            logger.info("Projet Keystone '%s' créé (id=%s).", name_projet, project_id)

            # Recuperation de l'id du role de l'utilisateur
            url_list_roles = f"{settings.KEYSTONE_URL}/roles?name={role}"
            role_lookup = requests.get(url_list_roles, headers=headers)
            roles = role_lookup.json().get('roles', [])
            role_id = roles[0]['id']

            # Recuperation de l'id du role de l'admin
            url_list_roles = f"{settings.KEYSTONE_URL}/roles?name=admin"
            role_lookup = requests.get(url_list_roles, headers=headers)
            roles = role_lookup.json().get('roles', [])
            role_id_admin = roles[0]['id']

            # Ajout de l'utilisateur dans le projet
            url_role = f"{settings.KEYSTONE_URL}/projects/{project_id}/users/{user_id}/roles/{role_id}"
            role_res = requests.put(url_role, headers=headers)

            url_admin = f"{settings.KEYSTONE_URL}/projects/{project_id}/users/{admin_id}/roles/{role_id_admin}"
            admin_res = requests.put(url_admin, headers=headers)

            url_barbican = f"{settings.KEYSTONE_URL}/projects/{project_id}/users/{barbican_id}/roles/{role_id_admin}"
            barbican_res = requests.put(url_barbican, headers=headers)

            if role_res.status_code == 204 and admin_res.status_code == 204 and barbican_res.status_code == 204:
                logger.info("Rôles assignés au projet %s (user, admin, barbican).", project_id)
            else:
                logger.warning(
                    "Erreur assignation rôle projet %s — user:%s admin:%s barbican:%s",
                    project_id,
                    role_res.status_code,
                    admin_res.status_code,
                    barbican_res.status_code,
                )

            return project_data
        else:
            logger.error("Erreur création projet Keystone : %s — %s", response.status_code, response.text)
            return None

    except requests.exceptions.RequestException as e:
        logger.error("Erreur connexion Keystone (creer_projet) : %s", e)
        return None

# Fonction pour creer les identifiants d'une application dans keystone
def creer_keystone_app_credential(user_token, user_id_keystone, name_app, description):
    url = f"{settings.KEYSTONE_URL}/users/{user_id_keystone}/application_credentials"
    headers = {"X-Auth-Token": user_token, "Content-Type": "application/json"}
    payload = {
        "application_credential": {
            "name": name_app,
            "description": description,
        }
    }

    try:
        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 201:
            logger.info("App Credential '%s' créé.", name_app)
            return response.json()['application_credential']
        else:
            logger.error("Erreur création App Credential '%s' : %s — %s",
                         name_app, response.status_code, response.text)
            return None

    except requests.exceptions.RequestException as e:
        logger.error("Erreur connexion Keystone (creer_app_credential) : %s", e)
        return None

# Fonction pour creer une application 
@login_required
def creer_app_view(request):
    if request.method != 'POST':
        # Restauration depuis la session si disponible (retour depuis creer_secret)
        form_data = request.session.get("creer_app_data", {})
        template = 'forms/creer_app_partiel.html' if request.headers.get('HX-Request') else 'forms/creer_app.html'
        return render(request, template, {"form_data": form_data})

    # Sauvegarde des données en session avant tout traitement
    request.session["creer_app_data"] = request.POST.dict()

    admin_token = get_admin_token()
    admin_id = get_user_keystone_id()
    barbican_id = get_user_barbican_id()
    logger.debug("creer_app_view: barbican_id=%s role=%s", barbican_id, request.user.role)
    nom_app = request.POST.get('name')
    description = request.POST.get('description')

    # --- VERIFICATION PREALABLE ---
    application_existante = Application.objects.filter(
        nom_app=nom_app,
        projet__utilisateur=request.user
    ).exists()

    if application_existante:
        return render(request, 'forms/creer_app_partiel.html', {
            'error': f"Vous possédez déjà une application nommée '{nom_app}'. Choisissez un autre nom !",
            "form_data": request.POST
        })

    # Création du Projet Keystone
    nom_projet_ks = f"{request.user.username}_{nom_app}_projet"
    project_data = creer_keystone_projet(admin_token, nom_projet_ks, description, request.user.id_keystone, admin_id, barbican_id, request.user.role)

    if not project_data:
        logger.error("creer_app_view: échec création projet Keystone pour '%s'.", nom_app)
        return render(request, 'forms/creer_app_partiel.html', {
            'error': "Veuillez reessayer plus tard !",
            "form_data": request.POST
        })

    # Création de l'Application Credential Keystone
    projet_id = project_data['id']
    token_actuel = request.session.get('keystone_token')
    user_token = token_keystone_scope(token_actuel, projet_id)
    app_cred_data = creer_keystone_app_credential(user_token, request.user.id_keystone, nom_app, description)

    if not app_cred_data:
        logger.error("creer_app_view: échec création App Credential Keystone pour '%s'.", nom_app)
        return render(request, 'forms/creer_app_partiel.html', {
            'error': "Veuillez reessayer plus tard !",
            "form_data": request.POST
        })

    # Sauvegarde en Base de Données Django
    try:
        app_obj = Application.objects.create(
            id_app=app_cred_data['id'],
            nom_app=nom_app,
            password_app=app_cred_data['secret'],
            description_app=description,
            role=request.user.role
        )
        Projet.objects.create(
            id_projet=project_data['id'],
            nom_projet=nom_projet_ks,
            application=app_obj,
            utilisateur=request.user
        )
        logger.info("Application '%s' créée par %s", nom_app, request.user.username)
        notifier_app_creee(request.user, nom_app)

        # Sauvegarde du nom de l'application en session pour la page de confirmation
        request.session["nouveau_app_nom"] = nom_app
        request.session['projet_id_actuel'] = projet_id

        template = (
            "secrets_manager/proposition_secret_partiel.html"
            if request.headers.get("HX-Request")
            else "secrets_manager/proposition_secret.html"
        )
        return render(request, template, {
            "projet_id": projet_id,
            "app_nom": nom_app,
        })

    except Exception as e:
        logger.error("creer_app_view: erreur BD pour '%s' : %s", nom_app, e, exc_info=True)
        return render(request, 'forms/creer_app_partiel.html', {
            'error': "Veuillez reessayer plus tard !",
            "form_data": request.POST
        })
#-----------------------------------------------------------------------------------------#


#-------------------------------- FONCTION D'AFFICHAGE -----------------------------------#

# Fonction pour recuperer la liste des applications de l'utilisateur
@login_required
def list_apps_view(request):
    q = request.GET.get('q', '').strip()
    sort = request.GET.get('sort', '')

    projets = (
        Projet.objects
        .filter(utilisateur=request.user)
        .select_related('application')
        .prefetch_related('conteneur__secret')
        .annotate(nb_secrets=Count('conteneur', distinct=True))
    )
    if q:
        q_filter = (
            Q(application__nom_app__icontains=q) |
            Q(conteneur__nom_conteneur__icontains=q)
        )
        # Filtre numérique sur duree_validite
        if q.isdigit():
            q_filter |= Q(conteneur__duree_validite=int(q))
        # Filtre date : année seule (ex: "2026")
        if re.match(r'^\d{4}$', q):
            q_filter |= Q(conteneur__date_expiration__year=int(q))
        # Filtre date : format français dd/mm/yyyy
        match_date = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{4})$', q)
        if match_date:
            try:
                d = date_type(int(match_date.group(3)), int(match_date.group(2)), int(match_date.group(1)))
                q_filter |= Q(conteneur__date_expiration__date=d)
            except ValueError:
                pass
        # Filtre par version
        if q.isdigit():
            q_filter |= Q(conteneur__version=int(q))
        # Filtre par type de secret
        q_lower = q.lower()
        for keyword, internal in {'api': 'generic', 'paire': 'rsa', 'ssl': 'certificate', 'tls': 'certificate', 'certificat': 'certificate'}.items():
            if keyword in q_lower:
                q_filter |= Q(conteneur__type_conteneur=internal)
        projets = projets.filter(q_filter).distinct()

    sort_map = {
        'nom_asc':     'application__nom_app',
        'nom_desc':    '-application__nom_app',
        'secrets_asc': 'nb_secrets',
        'secrets_desc':'-nb_secrets',
    }
    projets = projets.order_by(sort_map.get(sort, '-pk'))

    paginator = Paginator(projets, 6)
    page_obj = paginator.get_page(request.GET.get('page', 1))

    context = {'projets': page_obj, 'page_obj': page_obj, 'q': q, 'sort': sort}

    # Requête HTMX ciblant #apps-list (tri, recherche ou pagination) : liste seule
    if request.headers.get('HX-Request'):
        hx_target = request.headers.get('HX-Target', '')
        if 'q' in request.GET or 'page' in request.GET or hx_target == 'apps-list':
            return render(request, 'apps_manager/list_app_partiel.html', context)
        return render(request, 'apps_manager/list_app_content.html', context)

    # Accès direct : page complète
    return render(request, 'apps_manager/list_app_full.html', context)
#------------------------------------------------------------------------------------------#


# --------------------------------------------------------------------- #
# RECHERCHE GLOBALE                                                      #
# --------------------------------------------------------------------- #
@login_required
def recherche_view(request):
    q = request.GET.get('q', '').strip()

    projets = (
        Projet.objects.filter(utilisateur=request.user)
        .select_related('application')
        .prefetch_related('conteneur')
    )

    if q:
        q_lower = q.lower()
        type_filter = None
        for keyword, internal in {'api': 'generic', 'paire': 'rsa', 'ssl': 'certificate', 'tls': 'certificate', 'certificat': 'certificate'}.items():
            if keyword in q_lower:
                type_filter = internal
                break

        p_filter = (
            Q(application__nom_app__icontains=q) |
            Q(conteneur__nom_conteneur__icontains=q) |
            Q(conteneur__type_conteneur__icontains=q)
        )
        if type_filter:
            p_filter |= Q(conteneur__type_conteneur=type_filter)
        if q.isdigit():
            p_filter |= Q(conteneur__version=int(q))

        projets = projets.filter(p_filter).distinct()

    results = []
    for projet in projets:
        conteneurs_qs = ConteneurSecret.objects.filter(projet=projet)
        if q:
            q_lower = q.lower()
            type_filter = None
            for keyword, internal in {'api': 'generic', 'paire': 'rsa', 'ssl': 'certificate', 'tls': 'certificate', 'certificat': 'certificate'}.items():
                if keyword in q_lower:
                    type_filter = internal
                    break
            c_filter = Q(nom_conteneur__icontains=q) | Q(type_conteneur__icontains=q)
            if type_filter:
                c_filter |= Q(type_conteneur=type_filter)
            if q.isdigit():
                c_filter |= Q(version=int(q))

            app_name_match = q.lower() in (projet.application.nom_app.lower() if projet.application else '')
            matching = conteneurs_qs.filter(c_filter)
            results.append({
                'projet': projet,
                'conteneurs': conteneurs_qs if app_name_match else matching,
                'app_matches': app_name_match,
            })
        else:
            results.append({'projet': projet, 'conteneurs': conteneurs_qs, 'app_matches': True})

    context = {'q': q, 'results': results, 'total': len(results)}

    if request.headers.get('HX-Request'):
        return render(request, 'apps_manager/recherche_content.html', context)
    return render(request, 'apps_manager/recherche_full.html', context)


#------------------------------- FONCTIONS DE SUPPRESSION ---------------------------#

# Fonction pour supprimer un projet dans keystone
def supprimer_keystone_projet(admin_token, projet_id):
    url = f"{settings.KEYSTONE_URL}/projects/{projet_id}"
    headers = {"X-Auth-Token": admin_token, "Content-Type": "application/json"}
    
    try:
        response = requests.delete(url, headers=headers, timeout=10)
        
        # 204 = Succès, 404 = Déjà supprimé
        if response.status_code == 204:
            logger.info("Projet Keystone %s supprimé.", projet_id)
            return True
        elif response.status_code == 404:
            logger.warning("Projet Keystone %s introuvable (déjà supprimé ?).", projet_id)
            return True
        else:
            logger.error("Erreur suppression projet Keystone %s : %s — %s",
                         projet_id, response.status_code, response.text)
            return False
    except requests.exceptions.RequestException as e:
        logger.error("Erreur connexion Keystone (supprimer_projet) : %s", e)
        return False

# Fonction pour supprimer une application credential dans keystone
def supprimer_keystone_app_credential(user_token, user_id, app_id):
    url = f"{settings.KEYSTONE_URL}/users/{user_id}/application_credentials/{app_id}"
    headers = {"X-Auth-Token": user_token, "Content-Type": "application/json"}
    
    try:
        response = requests.delete(url, headers=headers, timeout=10)
        
        if response.status_code == 204:
            logger.info("App Credential %s supprimée.", app_id)
            return True
        elif response.status_code == 404:
            logger.warning("App Credential %s introuvable (déjà supprimée ?).", app_id)
            return True
        else:
            logger.error("Erreur suppression App Credential %s : %s — %s",
                         app_id, response.status_code, response.text)
            return False
    except requests.exceptions.RequestException as e:
        logger.error("Erreur connexion Keystone (supprimer_app_credential) : %s", e)
        return False

# Fonction pour supprimer une application
@login_required
def supprimer_app_view(request):

    id_projet_ks     = request.POST.get('id_projet')
    projet           = get_object_or_404(Projet, id_projet=id_projet_ks)
    application      = projet.application
    admin_token      = get_admin_token()
    user_token_actuel = request.session.get('keystone_token')
    user_token       = token_keystone_scope(user_token_actuel, id_projet_ks)
    user_id          = projet.utilisateur.id_keystone
    app_id           = application.id_app

    # --- ÉTAPE BARBICAN : suppression des conteneurs et secrets ---
    conteneurs = projet.conteneur.prefetch_related('secret').all()
    if conteneurs.exists():
        try:
            bc_user  = get_barbican_client(user_token, id_projet_ks)
            bc_admin = get_barbican_client(token_keystone_scope(admin_token, id_projet_ks), id_projet_ks)
            for conteneur in conteneurs:
                for secret in conteneur.secret.all():
                    supprimer_secret_barbican(bc_user, secret.ref_secret, bc_fallback=bc_admin)
                if conteneur.ref_old_conteneur:
                    supprimer_conteneur_barbican(bc_user, conteneur.ref_old_conteneur, bc_fallback=bc_admin)
                if conteneur.ref_new_conteneur:
                    supprimer_conteneur_barbican(bc_user, conteneur.ref_new_conteneur, bc_fallback=bc_admin)
            print(f"Conteneurs et secrets Barbican supprimés pour le projet {id_projet_ks}.")
            logger.info("Conteneurs et secrets Barbican supprimés pour le projet %s.", id_projet_ks)
        except BarbicanConnectionError as e:
            logger.warning("Erreur Barbican lors de la suppression de l'app %s : %s", app_id, e)

    # --- ÉTAPE KEYSTONE ---
    success_cred = supprimer_keystone_app_credential(user_token, user_id, app_id)
    success_proj = supprimer_keystone_projet(admin_token, id_projet_ks)

    # --- ÉTAPE BASE DE DONNÉES ---
    if success_cred and success_proj:
        try:
            nom_app_supprimee = application.nom_app
            # La suppression de application cascade vers projet → conteneur → secret
            application.delete()
            logger.info("Application '%s' supprimée par %s.", nom_app_supprimee, request.user.username)
            notifier_app_supprimee(request.user, nom_app_supprimee)
        except Exception as e:
            logger.error(f"Erreur BD lors de la suppression de '{application.nom_app}' : {str(e)}", exc_info=True)
    else:
        logger.error(f"Échec suppression Keystone pour le projet {id_projet_ks}.")

    return redirect('apps_manager:list_app')


# --------------------------------------------------------------------- #
# FONCTION POUR SUPPRIMER PLUSIEURS APPLICATIONS EN UNE FOIS            #
# --------------------------------------------------------------------- #
@login_required
def supprimer_apps_selection_view(request):
    if request.method != 'POST':
        return redirect('apps_manager:list_app')

    projet_ids = request.POST.getlist('projet_ids')
    supprimees = 0
    noms_supprimes = []

    for projet_id in projet_ids:
        try:
            projet      = Projet.objects.get(id_projet=projet_id, utilisateur=request.user)
            application = projet.application
            nom_app     = application.nom_app
            admin_token = get_admin_token()
            user_token  = token_keystone_scope(request.session.get('keystone_token'), projet_id)
            user_id     = projet.utilisateur.id_keystone
            app_id      = application.id_app

            conteneurs = projet.conteneur.prefetch_related('secret').all()
            if conteneurs.exists():
                try:
                    bc_user  = get_barbican_client(user_token, projet_id)
                    bc_admin = get_barbican_client(token_keystone_scope(admin_token, projet_id), projet_id)
                    for conteneur in conteneurs:
                        for secret in conteneur.secret.all():
                            supprimer_secret_barbican(bc_user, secret.ref_secret, bc_fallback=bc_admin)
                        if conteneur.ref_old_conteneur:
                            supprimer_conteneur_barbican(bc_user, conteneur.ref_old_conteneur, bc_fallback=bc_admin)
                        if conteneur.ref_new_conteneur:
                            supprimer_conteneur_barbican(bc_user, conteneur.ref_new_conteneur, bc_fallback=bc_admin)
                except BarbicanConnectionError as e:
                    logger.warning(f"Erreur Barbican suppression en masse {projet_id} : {e}")

            supprimer_keystone_app_credential(user_token, user_id, app_id)
            supprimer_keystone_projet(admin_token, projet_id)
            application.delete()
            noms_supprimes.append(nom_app)
            supprimees += 1
            logger.info(f"Application '{nom_app}' supprimée (sélection multiple).")
        except Projet.DoesNotExist:
            logger.warning(f"Projet {projet_id} introuvable lors de la suppression en masse.")
        except Exception as e:
            logger.error(f"Erreur suppression projet {projet_id} : {e}", exc_info=True)

    if supprimees:
        messages.success(request, f"{supprimees} application(s) supprimée(s) avec succès.")
        notifier_apps_supprimees_masse(request.user, noms_supprimes)

    response = HttpResponse()
    response['HX-Redirect'] = reverse('apps_manager:list_app')
    return response


# --------------------------------------------------------------------- #
# FONCTION POUR SUPPRIMER PLUSIEURS CONTENEURS EN UNE FOIS              #
# --------------------------------------------------------------------- #
@login_required
def supprimer_conteneurs_selection_view(request):
    if request.method != 'POST':
        return redirect('apps_manager:list_app')

    conteneur_ids = request.POST.getlist('conteneur_ids')
    projet_id     = request.POST.get('projet_id')
    supprimes     = 0
    noms_supprimes = []

    for conteneur_id in conteneur_ids:
        try:
            conteneur = ConteneurSecret.objects.get(id=conteneur_id, projet__utilisateur=request.user)
            pid        = conteneur.projet.id_projet
            user_token = token_keystone_scope(request.session.get('keystone_token'), pid)
            admin_tok  = get_admin_token()

            try:
                bc_user  = get_barbican_client(user_token, pid)
                bc_admin = get_barbican_client(token_keystone_scope(admin_tok, pid), pid)
                for secret in conteneur.secret.all():
                    supprimer_secret_barbican(bc_user, secret.ref_secret, bc_fallback=bc_admin)
                if conteneur.ref_old_conteneur:
                    supprimer_conteneur_barbican(bc_user, conteneur.ref_old_conteneur, bc_fallback=bc_admin)
                if conteneur.ref_new_conteneur:
                    supprimer_conteneur_barbican(bc_user, conteneur.ref_new_conteneur, bc_fallback=bc_admin)
            except BarbicanConnectionError as e:
                logger.warning(f"Erreur Barbican suppression conteneur {conteneur_id} : {e}")

            nom = conteneur.nom_conteneur
            conteneur.delete()
            noms_supprimes.append(nom)
            supprimes += 1
            logger.info(f"Conteneur '{nom}' supprimé (sélection multiple).")
        except ConteneurSecret.DoesNotExist:
            logger.warning(f"Conteneur {conteneur_id} introuvable.")
        except Exception as e:
            logger.error(f"Erreur suppression conteneur {conteneur_id} : {e}", exc_info=True)

    if supprimes:
        messages.success(request, f"{supprimes} secret(s) supprimé(s) avec succès.")
        notifier_secrets_supprimes_masse(request.user, noms_supprimes)

    response = HttpResponse()
    if projet_id:
        response['HX-Redirect'] = reverse('apps_manager:detail_app') + f'?projet_id={projet_id}'
    else:
        response['HX-Redirect'] = reverse('apps_manager:list_app')
    return response


# --------------------------------------------------------------------- #
# FONCTION POUR MODIFIER UNE APPLICATION (nom + description)           #
# --------------------------------------------------------------------- #
@login_required
def modifier_app_view(request):

    projet_id   = request.GET.get('projet_id') or request.POST.get('projet_id')
    projet      = get_object_or_404(Projet, id_projet=projet_id, utilisateur=request.user)
    application = projet.application

    # ── GET : afficher le formulaire pré-rempli ── #
    if request.method == 'GET':
        return render(request, 'apps_manager/modifier_app_partiel.html', {
            'projet':      projet,
            'application': application,
        })

    # ── POST : traiter les modifications ── #
    nouveau_nom_app      = request.POST.get('nom_app', '').strip()
    nouvelle_description = request.POST.get('description', '').strip()
    erreurs              = []

    user_token_actuel = request.session.get('keystone_token')
    user_token        = token_keystone_scope(user_token_actuel, projet_id)

    # --- Modification du nom de l'application ---
    if nouveau_nom_app and nouveau_nom_app != application.nom_app:
        if Projet.objects.filter(
            utilisateur=request.user,
            application__nom_app=nouveau_nom_app
        ).exclude(id_projet=projet_id).exists():
            erreurs.append(f"Une application nommée « {nouveau_nom_app} » existe déjà.")
        else:
            try:
                admin_token = get_admin_token()
                url_patch   = f"{settings.KEYSTONE_URL.rstrip('/')}/projects/{projet_id}"
                headers     = {"X-Auth-Token": admin_token, "Content-Type": "application/json"}
                resp = requests.patch(
                    url_patch,
                    json={"project": {"name": f"projet_{nouveau_nom_app}"}},
                    headers=headers,
                    timeout=10,
                )
                if resp.status_code not in (200, 204):
                    raise Exception(f"Keystone PATCH projet : {resp.status_code} - {resp.text}")

                supprimer_keystone_app_credential(user_token, projet.utilisateur.id_keystone, application.id_app)
                new_cred = creer_keystone_app_credential(
                    user_token,
                    projet.utilisateur.id_keystone,
                    nouveau_nom_app,
                    application.description_app,
                )
                if not new_cred:
                    raise Exception("Échec de la création du nouveau credential Keystone.")

                ancien_nom               = application.nom_app
                application.nom_app      = nouveau_nom_app
                application.id_app       = new_cred['id']
                application.password_app = new_cred['secret']
                application.save()
                projet.nom_projet = f"projet_{nouveau_nom_app}"
                projet.save()
                logger.info("Application renommée de '%s' en '%s' (projet %s).", ancien_nom, nouveau_nom_app, projet_id)
                notifier_app_modifiee(request.user, ancien_nom, nouveau_nom_app)

            except Exception as e:
                erreurs.append(f"Erreur modification nom application : {str(e)}")
                logger.error(f"Erreur modification nom app {projet_id} : {str(e)}", exc_info=True)

    # --- Modification de la description ---
    if nouvelle_description != application.description_app:
        application.description_app = nouvelle_description
        application.save()
        logger.info(f"Description mise à jour pour le projet {projet_id}.")

    # --- Réponse ---
    if erreurs:
        projet      = get_object_or_404(Projet, id_projet=projet_id)
        application = projet.application
        return render(request, 'apps_manager/modifier_app_partiel.html', {
            'projet':      projet,
            'application': application,
            'erreurs':     erreurs,
        })

    messages.success(request, f"Application « {application.nom_app} » modifiée avec succès.")
    response = HttpResponse()
    response['HX-Redirect'] = reverse('apps_manager:list_app')
    return response


# --------------------------------------------------------------------- #
# FONCTION POUR AFFICHER LE DETAIL D'UNE APPLICATION                   #
# --------------------------------------------------------------------- #
@login_required
def detail_app_view(request):
    projet_id   = request.GET.get('projet_id')
    projet      = get_object_or_404(Projet, id_projet=projet_id, utilisateur=request.user)
    application = projet.application
    conteneurs  = projet.conteneur.prefetch_related('secret').all()

    now = timezone.now()
    groupes = {'generic': [], 'rsa': [], 'certificate': []}
    for c in conteneurs:
        if c.type_conteneur in groupes:
            if c.date_expiration:
                delta = (c.date_expiration - now).days
                c.jours_restants = delta
                c.est_expire = delta < 0
            else:
                c.jours_restants = None
                c.est_expire = False
            groupes[c.type_conteneur].append(c)

    # Construire un dict {conteneur_id: TokenAcces} pour le template
    tous_ids = [c.id for gl in groupes.values() for c in gl]
    tokens_qs = TokenAcces.objects.filter(conteneur_id__in=tous_ids)
    tokens_map = {t.conteneur_id: t for t in tokens_qs}

    context = {
        'projet':      projet,
        'application': application,
        'groupes':     groupes,
        'tokens_map':  tokens_map,
    }

    if request.headers.get('HX-Request'):
        return render(request, 'apps_manager/detail_app_content.html', context)
    return render(request, 'apps_manager/detail_app_full.html', context)


# --------------------------------------------------------------------- #
# FONCTION POUR MODIFIER UN CONTENEUR (nom + durée)                    #
# --------------------------------------------------------------------- #
@login_required
def modifier_conteneur_view(request):
    conteneur_id = request.GET.get('conteneur_id') or request.POST.get('conteneur_id')
    conteneur    = get_object_or_404(ConteneurSecret, id=conteneur_id)
    projet       = conteneur.projet

    if projet.utilisateur != request.user:
        messages.error(request, "Action non autorisée.")
        return redirect('apps_manager:list_app')

    if request.method == 'GET':
        return render(request, 'apps_manager/modifier_conteneur_partiel.html', {
            'conteneur': conteneur,
            'projet':    projet,
        })

    nouveau_nom        = request.POST.get('nom_conteneur', '').strip()
    nouvelle_duree     = request.POST.get('duree_validite', '').strip()
    nouveau_delai      = request.POST.get('delai_anticipation', '').strip()
    erreurs            = []
    projet_id     = projet.id_projet

    user_token_actuel = request.session.get('keystone_token')
    user_token        = token_keystone_scope(user_token_actuel, projet_id)

    if nouveau_nom and nouveau_nom != conteneur.nom_conteneur:
        try:
            bc      = get_barbican_client(user_token, projet_id)
            resultat = renommer_secrets_conteneur_barbican(bc, conteneur, nouveau_nom)
            conteneur.nom_conteneur     = nouveau_nom
            conteneur.ref_old_conteneur = resultat['container_ref']
            conteneur.ref_new_conteneur = None
            conteneur.save()
            conteneur.secret.all().delete()
            for s_data in resultat['secrets']:
                Secret.objects.create(
                    conteneur=conteneur,
                    nom_secret=s_data['nom'],
                    type_secret=s_data['type_secret'],
                    ref_secret=s_data['ref'],
                )
            logger.info("Conteneur renommé en '%s' (projet %s).", nouveau_nom, projet_id)
            nom_app_modif = projet.application.nom_app if projet.application else projet.nom_projet
            notifier_secret_modifie(request.user, nouveau_nom, nom_app_modif)
        except BarbicanConnectionError as e:
            erreurs.append(f"Erreur Barbican lors du renommage : {str(e)}")
            logger.error(f"Erreur Barbican renommage conteneur {conteneur_id} : {e}", exc_info=True)

    if nouvelle_duree:
        try:
            duree_int = int(nouvelle_duree)
            if duree_int < 1:
                raise ValueError("La durée doit être d'au moins 1 jour.")
            if duree_int != conteneur.duree_validite:
                ancienne_expiration = conteneur.date_expiration or timezone.now()
                conteneur.duree_validite  = duree_int
                conteneur.date_expiration = ancienne_expiration + timedelta(days=duree_int)
                conteneur.save()
        except ValueError as e:
            erreurs.append(f"Durée de validité invalide : {str(e)}")

    if nouveau_delai:
        try:
            delai_int = int(nouveau_delai)
            if delai_int < 1:
                raise ValueError("Le délai doit être d'au moins 1 jour.")
            if delai_int != conteneur.delai_anticipation:
                conteneur.delai_anticipation = delai_int
                conteneur.save()
        except ValueError as e:
            erreurs.append(f"Délai d'anticipation invalide : {str(e)}")

    if erreurs:
        conteneur.refresh_from_db()
        return render(request, 'apps_manager/modifier_conteneur_partiel.html', {
            'conteneur': conteneur,
            'projet':    projet,
            'erreurs':   erreurs,
        })

    messages.success(request, f"Secret « {conteneur.nom_conteneur} » modifié avec succès.")
    response = HttpResponse()
    response['HX-Redirect'] = reverse('apps_manager:detail_app') + f'?projet_id={projet_id}'
    return response


# --------------------------------------------------------------------- #
# FONCTION POUR AFFICHER LE DASHBOARD                                   #
# --------------------------------------------------------------------- #
@login_required
def dashboard_view(request):
    from datetime import timedelta

    q = request.GET.get('q', '').strip()

    projets = Projet.objects.filter(utilisateur=request.user).prefetch_related('conteneur')
    all_conteneurs = ConteneurSecret.objects.filter(projet__utilisateur=request.user)

    if q:
        c_filter = (
            Q(nom_conteneur__icontains=q) |
            Q(type_conteneur__icontains=q) |
            Q(projet__application__nom_app__icontains=q)
        )
        p_filter = (
            Q(application__nom_app__icontains=q) |
            Q(conteneur__nom_conteneur__icontains=q) |
            Q(conteneur__type_conteneur__icontains=q)
        )
        q_lower = q.lower()
        for keyword, internal in {'api': 'generic', 'paire': 'rsa', 'ssl': 'certificate', 'tls': 'certificate', 'certificat': 'certificate'}.items():
            if keyword in q_lower:
                c_filter |= Q(type_conteneur=internal)
                p_filter |= Q(conteneur__type_conteneur=internal)
        if q.isdigit():
            c_filter |= Q(version=int(q))
            p_filter |= Q(conteneur__version=int(q))
        projets = projets.filter(p_filter).distinct()
        all_conteneurs = all_conteneurs.filter(c_filter).distinct()

    total_apps = projets.count()
    total_secrets = all_conteneurs.count()

    # Distribution par type
    generic_count     = all_conteneurs.filter(type_conteneur='generic').count()
    rsa_count         = all_conteneurs.filter(type_conteneur='rsa').count()
    certificate_count = all_conteneurs.filter(type_conteneur='certificate').count()

    # Apps avec / sans secrets
    apps_with_secrets    = projets.filter(conteneur__isnull=False).distinct().count()
    apps_without_secrets = total_apps - apps_with_secrets

    # Secrets renouvelés (version > 1)
    renewed_count     = all_conteneurs.filter(version__gt=1).count()
    not_renewed_count = total_secrets - renewed_count

    # Tri du tableau des prochains renouvellements
    sort_by = request.GET.get('sort', 'date_asc')
    sort_map = {
        'date_asc':    'date_expiration',
        'date_desc':   '-date_expiration',
        'app_asc':     'projet__application__nom_app',
        'app_desc':    '-projet__application__nom_app',
        'secret_asc':  'nom_conteneur',
        'secret_desc': '-nom_conteneur',
        'type_asc':    'type_conteneur',
        'type_desc':   '-type_conteneur',
    }
    order = sort_map.get(sort_by, 'date_expiration')

    # Prochains renouvellements (30 prochains jours)
    now = timezone.now()
    upcoming_qs = (
        all_conteneurs
        .filter(date_expiration__gte=now, date_expiration__lte=now + timedelta(days=30))
        .select_related('projet__application')
        .order_by(order)
    )
    # Pagination des prochains renouvellements (4 par page)
    page_upcoming    = request.GET.get('page_upcoming', 1)
    paginator_upcoming = Paginator(upcoming_qs, 4)
    page_obj_upcoming  = paginator_upcoming.get_page(page_upcoming)

    # Pré-calcul des jours restants pour le template
    upcoming = []
    for c in page_obj_upcoming:
        c.jours_restants = max(0, (c.date_expiration - now).days)
        upcoming.append(c)

    context = {
        'total_apps':           total_apps,
        'total_secrets':        total_secrets,
        'generic_count':        generic_count,
        'rsa_count':            rsa_count,
        'certificate_count':    certificate_count,
        'apps_with_secrets':    apps_with_secrets,
        'apps_without_secrets': apps_without_secrets,
        'renewed_count':        renewed_count,
        'not_renewed_count':    not_renewed_count,
        'upcoming':             upcoming,
        'page_obj_upcoming':    page_obj_upcoming,
        'sort_by':              sort_by,
        'q':                    q,
    }

    if request.headers.get('HX-Request'):
        return render(request, 'dashboard/dashboard_content.html', context)
    return render(request, 'dashboard/dashboard_full.html', context)


# --------------------------------------------------------------------- #
# FONCTION POUR SUPPRIMER UN CONTENEUR ET SES SECRETS                  #
# --------------------------------------------------------------------- #
@login_required
def supprimer_conteneur_view(request):
    if request.method != 'POST':
        return redirect('apps_manager:list_app')

    conteneur_id = request.POST.get('conteneur_id')
    conteneur    = get_object_or_404(ConteneurSecret, id=conteneur_id)
    projet       = conteneur.projet

    if projet.utilisateur != request.user:
        messages.error(request, "Action non autorisée.")
        return redirect('apps_manager:list_app')

    projet_id         = projet.id_projet
    user_token_actuel = request.session.get('keystone_token')
    user_token        = token_keystone_scope(user_token_actuel, projet_id)
    admin_tok         = get_admin_token()

    try:
        bc_user  = get_barbican_client(user_token, projet_id)
        bc_admin = get_barbican_client(token_keystone_scope(admin_tok, projet_id), projet_id)
        for secret in conteneur.secret.all():
            supprimer_secret_barbican(bc_user, secret.ref_secret, bc_fallback=bc_admin)
        if conteneur.ref_old_conteneur:
            supprimer_conteneur_barbican(bc_user, conteneur.ref_old_conteneur, bc_fallback=bc_admin)
        if conteneur.ref_new_conteneur:
            supprimer_conteneur_barbican(bc_user, conteneur.ref_new_conteneur, bc_fallback=bc_admin)
    except BarbicanConnectionError as e:
        logger.warning(f"Erreur Barbican suppression conteneur {conteneur_id} : {e}")

    nom = conteneur.nom_conteneur
    nom_app_suppr = projet.application.nom_app if projet.application else projet.nom_projet
    conteneur.delete()
    logger.info("Conteneur '%s' supprimé (projet %s).", nom, projet_id)
    notifier_secret_supprime(request.user, nom, nom_app_suppr)
    messages.success(request, f"Secret « {nom} » supprimé avec succès.")

    response = HttpResponse()
    response['HX-Redirect'] = reverse('apps_manager:detail_app') + f'?projet_id={projet_id}'
    return response
