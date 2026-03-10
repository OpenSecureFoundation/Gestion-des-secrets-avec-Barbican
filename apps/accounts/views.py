from pyexpat.errors import messages

from django.http import HttpResponse
from django.urls import reverse
import requests
from django.shortcuts import redirect, render
from django.conf import settings 
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from .models import Utilisateur

################################### FONCTIONS NECESSAIRES POUR L'AUTHENTIFICATION ################################################

# Fonction pour construire le JSON de la requete d'authentification
def _generer_requete_auth(pseudo, mdp, methode="password", domaine="Default", scope=None):
    url_auth = f"{settings.KEYSTONE_URL}/auth/tokens"
    auth_data = {
        "auth": {
            "identity": {
                "methods": [methode],
                "password": {
                    "user": {
                        "name": pseudo,
                        "domain": {"name": domaine},
                        "password": mdp
                    }
                }
            }
        }
    }
    # Si un scope est fourni, on l'ajoute au dictionnaire
    if scope:
        auth_data["auth"]["scope"] = scope
    
    headers_auth = {"Content-Type": "application/json"}

    return url_auth, auth_data, headers_auth

# Fonction d'authentification pour simple vérification d'identité
def token_verification(pseudo, mdp):
    url, data, headers = _generer_requete_auth(pseudo=pseudo, mdp=mdp)
    
    response = requests.post(url, json=data, headers=headers)
    
    if response.status_code == 201:
        return response.headers.get('X-Subject-Token')
    return None

# Fonction d'authentification pour attribution de permission sur un projet
def token_acces(pseudo, mdp, projet, domaine="Default", methode="password"):
    scope = {
        "project": {
            "name": projet,
            "domain": {"name": domaine}
        }
    }
    url, data, headers = _generer_requete_auth(pseudo, mdp, methode, domaine, scope=scope)
    
    response = requests.post(url, json=data, headers=headers)
    
    if response.status_code == 201:
        return response.headers.get('X-Subject-Token')
    return None

# Fonction de creation du token de l'administrateur de keystone
def get_admin_token():
    pseudo = settings.KEYSTONE_ADMIN_USERNAME
    domaine = settings.KEYSTONE_ADMIN_DOMAIN
    mdp = settings.KEYSTONE_ADMIN_PASSWORD
    projet = settings.KEYSTONE_ADMIN_PROJECT
       
    try:
        return token_acces(pseudo=pseudo, mdp=mdp, projet=projet, domaine=domaine)    ####### Amelioration possible au niveau de la methode. Faut il prendre en compte d'autres methodes? Si oui comment?
    except Exception as e:
        print(f"Erreur de connexion pour le token: {e}. Verifiez vos parametres administrateurs")
        return None
###############################################################################################################################


################################## FONCTIONS PROPRES AUX UTILISATEURS ############################


# Fonction pour la creation d'un utilisateur dans KEYSTONE
def creer_utilisateur_keystone(pseudonyme, password, email):
    token = get_admin_token()
    
    if not token:
        print("Impossible de se connecter au serveur Keystone. Verifiez que votre serveur Keystone est actif.")
        return None

    # On recupere l'URL du serveur KEYSTONE pour la création d'utilisateur
    url_users = f"{settings.KEYSTONE_URL}/users"

    headers = {
        "X-Auth-Token": token,
        "Content-Type": "application/json"
    }

    data = {
        "user": {
            "name": pseudonyme, 
            "password": password, 
            "email": email, 
            "enabled": True
        }
    }

    try:
        response = requests.post(url_users, headers=headers, json=data)
        
        if response.status_code == 201:
            # Succès : On récupère l'ID généré par Keystone 
            return response.json()['user']['id'] 
        else:
            print(f"Erreur cote serveur Keystone: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Erreur de connexion au serveur Keystone: {e}. Verifiez que votre serveur Keystone est actif.")
        return None

# Fonction pour stocker un nouvel utilisateur dans la base de donnees locale
def register_view(request):
    if request.method == "POST":
        # Récupération des données du formulaire 
        prenom = request.POST.get('first_name')
        nom = request.POST.get('last_name')
        pseudo = request.POST.get('username') # Utilisé comme pseudonyme
        email_saisi = request.POST.get('email')
        mdp = request.POST.get('password') 
        confirm_mdp = request.POST.get('confirm_password')       

        # --- VÉRIFICATION DES MOTS DE PASSE ---
        if mdp != confirm_mdp:
            return render(request, 'forms/register.html', {
                "error": "Mots de passe differents",
                "form_data": request.POST # Pour ne pas vider le formulaire
            })
        # ---------------------------------------

        # Reucperation de l'id_keystone genere.
        id_ks = creer_utilisateur_keystone(pseudo, mdp, email_saisi)

        if id_ks:
            try:
                # Insertion dans la base de donnees locale
                Utilisateur.objects.create_user(
                    username=pseudo,    
                    first_name=prenom,  
                    last_name=nom,      
                    email=email_saisi,  
                    password=mdp,       
                    id_keystone=id_ks,  
                    role="member"       
                )
                response = HttpResponse()
                response['HX-Redirect'] = reverse('accounts:login')  
                return response
            except Exception as e:
                print(f"Erreur d'enregistrement dans la base de données locale : {e}")
                return render(request, 'forms/register.html', {
                    "error": "Données invalides",
                    "form_data": request.POST
                })
        else:
            return render(request, 'forms/register.html', {
                "error": "Données invalides",
                "form_data": request.POST
            })

    return render(request, 'forms/register.html')

# Fonction pour la connexion dans notre application
def login_view(request):
    if request.method == "POST":
        pseudo = request.POST.get('username')
        mdp = request.POST.get('password')
        
        # Validation Keystone
        keystone_token = token_verification(pseudo, mdp)
        
        if keystone_token:
            # Récupération de l'utilisateur dans la DB locale
            try:
                user = Utilisateur.objects.get(username=pseudo)
                
                # Connection de l'utilisateur 
                login(request, user)
                # STOCKAGE DU TOKEN DANS LA SESSION
                request.session['keystone_token'] = keystone_token
                # Redirection vers la page principale#############################################################################################33
                response = HttpResponse()
                response['HX-Redirect'] = reverse('accounts:profile')  
                return response
                
            except Utilisateur.DoesNotExist:
                return render(request, 'forms/login.html', {
                    "error": "Identifiants invalides.",
                    "form_data": request.POST
                })
        else:
            return render(request, 'forms/login.html', {
                "error": "Identifiants invalides.",
                "form_data": request.POST
                })

    return render(request, 'forms/login.html')


# Fonction pour se deconnecter de son compte utilisateur
def logout_view(request):
    logout(request)
    messages.info(request, "Vous avez été déconnecté.")
    return redirect('accounts:login')

# Fonction pour supprimer un utilisateur dans keystone
def supprimer_utilisateur_keystone(admin_token, user_keystone_id):
    url = f"{settings.KEYSTONE_URL}/users/{user_keystone_id}"
    
    headers = {
        "X-Auth-Token": admin_token,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.delete(url, headers=headers)
      
        # Keystone renvoie 204 No Content en cas de succès
        if response.status_code == 204:
            print(f"Utilisateur supprimé avec succès: {response.status_code} - {response.text}")
            return True
        else:
            print(f"Erreur cote serveur Keystone: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Erreur de connexion : {str(e)}")
        return False
    
# Fonction pour supprimer son compte utilisateur de BarbiLink
@login_required
def supprimer_compte_view(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        user = request.user
              
        # Vérification du mot de passe pour la sécurité
        if not user.check_password(password):
            return render(request, 'forms/confirm_supp_partiel.html', {
                    "error": "Mot de passe incorrect.",
                    "form_data": request.POST
                })

        try:
            # Recuperation du token de l'administrateur
            admin_token = get_admin_token()

             # Recuperation de l'id keystone de l'utilisateur
            id_ks_user = user.id_keystone

            # Suppression dans Keystone d'abord
            keystone_deleted = supprimer_utilisateur_keystone(admin_token, id_ks_user)
            
            if keystone_deleted:
                # Suppression dans la base de donnees locale et déconnexion
                user.delete()
                print("Compte et accès Keystone supprimés avec succès.")
                logout(request)
                response = HttpResponse()
                response['HX-Redirect'] = reverse('accounts:login')  
                return response
            else:
                print("Erreur lors de la suppression sur le serveur d'identité.")
                return render(request, 'forms/confirm_supp_partiel.html', {
                    "error": "Veuillez reessayer plus tard !",
                    "form_data": request.POST
                })
                
        except Exception as e:
            print(f"Une erreur critique est survenue : {str(e)}")
            return render(request, 'forms/confirm_supp_partiel.html', {
                "error": "Veuillez reessayer plus tard !",
                "form_data": request.POST
            })
    return render(request, 'forms/confirm_suppression.html')

# Fonction pour mettre à jour un utilisateur dans Keystone
def modifier_utilisateur_keystone(request, admin_token, user_id, name=None, password=None, email=None):
    url = f"{settings.KEYSTONE_URL}/users/{user_id}"
    headers = {
        "X-Auth-Token": admin_token,
        "Content-Type": "application/json"
    }
    
    # Construction du corps de la requête (payload)
    # On ne met que les champs qui ne sont pas None
    user_data = {}
    if name: user_data['name'] = name
    if password: user_data['password'] = password
    if email: user_data['email'] = email
    
    payload = {"user": user_data}
    print(payload) ##################
    try:
        response = requests.patch(url, json=payload, headers=headers)
        
        if response.status_code == 200:
            return True
        else:
            print(f"Erreur Keystone ({response.status_code}): {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"Erreur de connexion à Keystone: {e}")
        return False
    
# Fonction pour modifier l'identite de l'utilisateur
@login_required
def change_identity_view(request):
    if request.method == 'POST':
        user = request.user
        
        # Récupération des valeurs postées
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')

        admin_token = get_admin_token()
        
        # Recuperation des donnees actuelles de l'utilisateur
        user_id = user.id_keystone       

        # Préparation des données pour Keystone (uniquement ce qui change)
        if username and username != user.username :
            success1 = modifier_utilisateur_keystone(request, admin_token, user_id, name=username)
            if not success1:
                    print(f"Erreur : échec de la mise à jour Keystone.")
                    return render(request, 'accounts/profile.html', {
                        "error_message": "Veuillez reessayer plus tard !",
                        "form_data": request.POST
                    })
        if email and email != user.email:
            success2 = modifier_utilisateur_keystone(request, admin_token, user_id, email=email)
            if not success2:
                    print(f"Erreur : échec de la mise à jour Keystone.")
                    return render(request, 'accounts/profile.html', {
                        "error_message": "Veuillez reessayer plus tard !",
                        "form_data": request.POST
                    })

        # Mise à jour de l'utilisateur Django
        if first_name: user.first_name = first_name
        if last_name: user.last_name = last_name
        if username: user.username = username
        if email: user.email = email
        
        user.save()
        return render(request, 'accounts/section_identite.html', {
            'user': user, 
            'success_message': "Identité modifiée avec succès !"
            })

    return render(request, 'accounts/profile.html')

# Fonction pour modifier le mot de passe
@login_required
def change_password_view(request):
    if request.method == 'POST':
        user = request.user
        old_pass = request.POST.get('old_password')
        new_pass = request.POST.get('new_password')
        conf_pass = request.POST.get('confirm_password')

        # Vérification de l'ancien mot de passe
        if not user.check_password(old_pass):
            return render(request, 'accounts/section_password.html', {
                'error_message': "Ancien mot de passe incorrect.",
                "form_data": request.POST
                })
        
        # Vérification de correspondance
        if not new_pass or new_pass != conf_pass:
            return render(request, 'accounts/section_password.html', {
                'error_message': "Les nouveaux mots de passe ne correspondent pas.",
                "form_data": request.POST
                })

        # Synchronisation Keystone
        admin_token = get_admin_token()
        user_id = user.id_keystone
        success = modifier_utilisateur_keystone(request, admin_token, user_id, password=new_pass)
        
        if not success:
            print("Erreur de synchronisation avec le serveur Keystone.")
            return render(request, 'accounts/section_password.html', {
                'error_message': "Veuillez reessayer plus tard !",
                "form_data": request.POST
                })

        # 4. Mise à jour Django
        user.set_password(new_pass)
        user.save()
        update_session_auth_hash(request, user)
        
        # Succès : On renvoie le formulaire vide avec un message positif
        return render(request, 'accounts/section_password.html', {
            'success_message': "Mot de passe modifié avec succès !"
            })
            
    return redirect('accounts:profile')

# Fonction pour recuperer le profile de l'utilisateur connecte
@login_required
def profile_view(request):
    # Si requête HTMX, retourner uniquement le contenu
    if request.headers.get('HX-Request'):
        return render(request, 'accounts/profile_partiel.html', {'user': request.user})
    
    # Sinon, retourner la page complète
    return render(request, 'accounts/profile.html', {'user': request.user})
