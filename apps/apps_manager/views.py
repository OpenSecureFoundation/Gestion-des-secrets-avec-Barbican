from pyexpat.errors import messages

from django.shortcuts import get_object_or_404, redirect, render
import requests
from django.conf import settings
from accounts.views import get_admin_token, get_user_barbican_id, get_user_keystone_id, token_keystone_scope
from apps_manager.models import Application, Projet
from django.contrib.auth.decorators import login_required

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
            print(f"Projet créé avec succès: {response.status_code}")

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
                print(f"Utilisateur ajouté au projet: {role_res.status_code}")
                print("Admin auto-assigné au projet avec succès.")
                print("Utilisateur Barbican ajouté au projet avec succès.")
            else:
                print(f"Erreur lors de l'ajout de l'utilisateur: {role_res.status_code} - {role_res.text}")
        
            return project_data
        else:
            print(f"Erreur création projet: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erreur de connexion au serveur keystone: {str(e)}")
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
            print(f"App Credential '{name_app}' créé avec succès: {response.status_code}")
            return response.json()['application_credential']
        else:
            print(f"Erreur création App Credential: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Erreur de connexion : {str(e)}")
        return None

# Fonction pour creer une application 
@login_required
def creer_app_view(request):
    if request.method != 'POST':
        # Restauration depuis la session si disponible (retour depuis creer_secret)
        form_data = request.session.get("creer_app_data", {})
        return render(request, 'forms/creer_app.html', {"form_data": form_data})

    # Sauvegarde des données en session avant tout traitement
    request.session["creer_app_data"] = request.POST.dict()

    admin_token = get_admin_token()
    admin_id = get_user_keystone_id()
    barbican_id = get_user_barbican_id()
    print(f"\n\n\n{barbican_id}\n\n\n") ###333######3333333333333333333333333333333#########
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
    nom_projet_ks = f"projet_{nom_app}"
    project_data = creer_keystone_projet(admin_token, nom_projet_ks, description, request.user.id_keystone, admin_id, barbican_id, request.user.role)

    if not project_data:
        print("Erreur lors de la creation du projet dans Keystone")
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
        print("Erreur lors de la creation des credential dans Keystone")
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
        print(f"L'application {nom_app} a été créée avec succès !")

        # Sauvegarde du nom de l'application en session pour la page de confirmation
        request.session["nouveau_app_nom"] = nom_app

        return redirect("secrets_manager:proposition_secret")

    except Exception as e:
        print(f"Erreur lors du stockage dans la base de donnees: {str(e)}")
        return render(request, 'forms/creer_app_partiel.html', {
            'error': "Veuillez reessayer plus tard !",
            "form_data": request.POST
        })
#-----------------------------------------------------------------------------------------#


#-------------------------------- FONCTION D'AFFICHAGE -----------------------------------#

# Fonction pour recuperer la liste des applications de l'utilisateur
@login_required
def list_apps_view(request):
    # On récupère tous les projets de l'utilisateur connecté avec l'application liée
    projets = Projet.objects.filter(utilisateur=request.user).select_related('application')
    projets = Projet.objects.filter(utilisateur=request.user)
    context = {'projets': projets}
    
    # Si c'est HTMX, on ne veut pas la base.html
    if request.headers.get('HX-Request'):
        return render(request, 'apps_manager/list_app_content.html', context)
    
    # Sinon (accès direct via l'URL), on renvoie tout avec base.html
    return render(request, 'apps_manager/list_app_full.html', context)
#------------------------------------------------------------------------------------------#


#------------------------------- FONCTIONS DE SUPPRESSION ---------------------------# 

# Fonction pour supprimer un projet dans keystone
def supprimer_keystone_projet(admin_token, projet_id):
    url = f"{settings.KEYSTONE_URL}/projects/{projet_id}"
    headers = {"X-Auth-Token": admin_token, "Content-Type": "application/json"}
    
    try:
        response = requests.delete(url, headers=headers, timeout=10)
        
        # 204 = Succès, 404 = Déjà supprimé
        if response.status_code == 204:
            print(f"Projet {projet_id} supprimé.")
            return True
        elif response.status_code == 404:
            print(f"Projet {projet_id} inexistant.")
            return True
        else:
            print(f"Erreur lors de la suppression dans Keystone Keystone Projet: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Erreur de connexion a keystone pour supprimer le projet: {str(e)}")
        return False

# Fonction pour supprimer une application credential dans keystone
def supprimer_keystone_app_credential(user_token, user_id, app_id):
    url = f"{settings.KEYSTONE_URL}/users/{user_id}/application_credentials/{app_id}"
    headers = {"X-Auth-Token": user_token, "Content-Type": "application/json"}
    
    try:
        response = requests.delete(url, headers=headers, timeout=10)
        
        if response.status_code == 204:
            print(f"App Credential {app_id} supprimée.")
            return True
        elif response.status_code == 404:
            print(f"App Credential {app_id} inexistante.")
            return True
        else:
            print(f"Erreur lors de la suppression dans Keystone App Cred: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Erreur de connexion a keystone pour supprimer l'app credential: {str(e)}")
        return False

# Fonction pour supprimer une application
@login_required
def supprimer_app_view(request):
    
    # Récupérer l'ID envoyé par le formulaire
    id_projet_ks = request.POST.get('id_projet')
        
    # Récupérer l'objet Projet (et son application liée)
    projet = get_object_or_404(Projet, id_projet=id_projet_ks)
    application = projet.application
    
    # Récupérer les jetons nécessaires
    # On utilise le token admin pour le projet et le token user pour le credential
    admin_token = get_admin_token() # Votre fonction pour obtenir le token admin
    user_token_actuel = request.session.get('keystone_token')
    user_token = token_keystone_scope(user_token_actuel, id_projet_ks)
    
    user_id = projet.utilisateur.id_keystone
    app_id = application.id_app

    # --- ÉTAPE KEYSTONE ---
    
    # On commence par le credential (important de le faire avant le projet)
    success_cred = supprimer_keystone_app_credential(user_token, user_id, app_id)
    
    # Ensuite on supprime le projet (avec le token admin)
    success_proj = supprimer_keystone_projet(admin_token, id_projet_ks)

    # --- ÉTAPE BASE DE DONNÉES ---

    if success_cred and success_proj:
        try:
            # Suppression en cascade dans Django
            # On supprime l'application et le projet
            application.delete() 
            projet.delete()
            
            print(f"L'application '{application.nom_app}' a été supprimée avec succès.")
        except Exception as e:
            print(f"Erreur lors du nettoyage de la base de données : {str(e)}")
    else:
        print("La suppression dans Keystone a échoué. L'opération a été annulée.")

    return redirect('apps_manager:list_app') 
