import logging
import random
import string
import time

from django.core.mail import send_mail
from django.http import HttpResponse
from django.urls import reverse
import requests
from django.shortcuts import redirect, render
from django.conf import settings
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from .models import Utilisateur
from api_manager.notifications import notifier_inscription


def _generer_code_verif():
    """Génère un code numérique à 6 chiffres."""
    return ''.join(random.choices(string.digits, k=6))


def _envoyer_code_verif(user, code, action):
    """Envoie le code de vérification par e-mail."""
    action_txt = "modification de votre identité" if action == "identite" else "modification de votre mot de passe"
    send_mail(
        subject=f"BarbiLink — Code de vérification : {code}",
        message=(
            f"Bonjour {user.first_name or user.username},\n\n"
            f"Un code de vérification est requis pour la {action_txt} :\n\n"
            f"    {code}\n\n"
            f"Ce code est valable 10 minutes.\n"
            f"Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=True,
    )

logger = logging.getLogger(__name__)

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


# Fonction pour generer un nouveau token scopé sur un projet spécifique
def token_keystone_scope(token_actuel, project_id):
    url = f"{settings.KEYSTONE_URL}/auth/tokens"
    logger.debug("token_keystone_scope: scoping sur projet %s", project_id)
    payload = {
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": {"id": token_actuel}
            },
            "scope": {
                "project": {"id": project_id}
            }
        }
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 201:
            nouveau_token = response.headers.get('X-Subject-Token')
            logger.debug("token_keystone_scope: nouveau token généré pour projet %s", project_id)
            return nouveau_token
        else:
            logger.error(
                "token_keystone_scope: re-scoping erreur %s — %s",
                response.status_code, response.text,
            )
            return None
    except requests.exceptions.RequestException as e:
        logger.error("token_keystone_scope: erreur réseau: %s", e)
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
        token = response.headers.get('X-Subject-Token')
        data = response.json()
        admin_id = data['token']['user']['id']
        return token, admin_id
    return None


# Fonction de recuperation du token de l'administrateur de keystone
def get_admin_token():
    pseudo  = settings.KEYSTONE_ADMIN_USERNAME
    domaine = settings.KEYSTONE_ADMIN_DOMAIN
    mdp     = settings.KEYSTONE_ADMIN_PASSWORD
    projet  = settings.KEYSTONE_ADMIN_PROJECT
    try:
        var = token_acces(pseudo=pseudo, mdp=mdp, projet=projet, domaine=domaine)
        return var[0]
    except Exception as e:
        logger.error("get_admin_token: impossible de récupérer le token admin: %s", e)
        return None


# Fonction de recuperation de l'id de l'utilisateur keystone
def get_user_keystone_id():
    pseudo  = settings.KEYSTONE_ADMIN_USERNAME
    domaine = settings.KEYSTONE_ADMIN_DOMAIN
    mdp     = settings.KEYSTONE_ADMIN_PASSWORD
    projet  = settings.KEYSTONE_ADMIN_PROJECT
    try:
        var = token_acces(pseudo=pseudo, mdp=mdp, projet=projet, domaine=domaine)
        return var[1]
    except Exception as e:
        logger.error("get_user_keystone_id: impossible de récupérer l'id admin: %s", e)
        return None


# Fonction de recuperation de l'id de l'utilisateur barbican
def get_user_barbican_id():
    pseudo  = settings.BARBICAN_USERNAME
    domaine = settings.KEYSTONE_ADMIN_DOMAIN
    mdp     = settings.BARBICAN_PASSWORD
    projet  = settings.BARBICAN_PROJECT
    try:
        var = token_acces(pseudo=pseudo, mdp=mdp, projet=projet, domaine=domaine)
        return var[1]
    except Exception as e:
        logger.error("get_user_barbican_id: impossible de récupérer l'id barbican: %s", e)
        return None

###############################################################################################################################


################################## FONCTIONS PROPRES AUX UTILISATEURS ############################


# Fonction pour la creation d'un utilisateur dans KEYSTONE
def creer_utilisateur_keystone(pseudonyme, password, email):
    token = get_admin_token()

    if not token:
        logger.error("creer_utilisateur_keystone: token admin indisponible — Keystone injoignable ?")
        return None

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
            return response.json()['user']['id']
        else:
            logger.error(
                "creer_utilisateur_keystone: erreur Keystone %s — %s",
                response.status_code, response.text,
            )
            return None
    except Exception as e:
        logger.error("creer_utilisateur_keystone: erreur de connexion: %s", e)
        return None


# Fonction pour stocker un nouvel utilisateur dans la base de donnees locale
def register_view(request):
    if request.method == "POST":
        prenom        = request.POST.get('first_name', '').strip()
        nom           = request.POST.get('last_name', '').strip()
        pseudo        = request.POST.get('username', '').strip()
        email_saisi   = request.POST.get('email', '').strip()
        mdp           = request.POST.get('password', '')
        confirm_mdp   = request.POST.get('confirm_password', '')

        if mdp != confirm_mdp:
            return render(request, 'forms/register.html', {
                "error": "Les mots de passe ne correspondent pas.",
                "form_data": request.POST
            })

        if Utilisateur.objects.filter(username=pseudo).exists():
            return render(request, 'forms/register.html', {
                "error": "Ce pseudonyme est déjà utilisé.",
                "form_data": request.POST
            })

        if Utilisateur.objects.filter(email=email_saisi).exists():
            return render(request, 'forms/register.html', {
                "error": "Cette adresse mail est déjà associée à un compte.",
                "form_data": request.POST
            })

        # Génération et envoi du code de vérification
        code = _generer_code_verif()
        request.session['verif_code_register']    = code
        request.session['verif_expires_register'] = time.time() + 600
        request.session['pending_register'] = {
            'first_name': prenom,
            'last_name':  nom,
            'username':   pseudo,
            'email':      email_saisi,
            'password':   mdp,
        }

        send_mail(
            subject=f"BarbiLink — Code de vérification : {code}",
            message=(
                f"Bonjour {prenom},\n\n"
                f"Voici votre code de vérification pour créer votre compte BarbiLink :\n\n"
                f"    {code}\n\n"
                f"Ce code est valable 10 minutes.\n\n"
                f"Si vous n'avez pas demandé à créer un compte, ignorez cet e-mail.\n\n"
                f"L'équipe BarbiLink"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email_saisi],
            fail_silently=True,
        )
        logger.info("register_view: code de vérification envoyé à %s", email_saisi)

        return render(request, 'forms/register_verify.html', {
            'user_email': email_saisi,
        })

    return render(request, 'forms/register.html')


def verify_register_view(request):
    if request.method != "POST":
        return redirect('accounts:register')

    code_saisi  = request.POST.get('verif_code', '').strip()
    code_attendu = request.session.get('verif_code_register')
    expires      = request.session.get('verif_expires_register', 0)
    pending      = request.session.get('pending_register')

    def _erreur(msg):
        return render(request, 'forms/register_verify.html', {
            'user_email': pending.get('email', '') if pending else '',
            'error': msg,
        })

    if not pending or not code_attendu:
        return redirect('accounts:register')

    if time.time() > expires:
        for k in ('verif_code_register', 'verif_expires_register', 'pending_register'):
            request.session.pop(k, None)
        return render(request, 'forms/register.html', {
            'error': "Le code a expiré. Veuillez recommencer.",
        })

    if code_saisi != code_attendu:
        return _erreur("Code incorrect. Vérifiez votre e-mail et réessayez.")

    # Code valide — création du compte
    prenom      = pending['first_name']
    nom         = pending['last_name']
    pseudo      = pending['username']
    email_saisi = pending['email']
    mdp         = pending['password']

    id_ks = creer_utilisateur_keystone(pseudo, mdp, email_saisi)

    if not id_ks:
        for k in ('verif_code_register', 'verif_expires_register', 'pending_register'):
            request.session.pop(k, None)
        return render(request, 'forms/register.html', {
            'error': "Impossible de créer le compte. Veuillez réessayer.",
        })

    try:
        nouvel_user = Utilisateur.objects.create_user(
            username=pseudo,
            first_name=prenom,
            last_name=nom,
            email=email_saisi,
            password=mdp,
            id_keystone=id_ks,
            role="creator"
        )
        notifier_inscription(nouvel_user)
        logger.info("verify_register_view: compte créé pour %s", pseudo)
    except Exception as e:
        logger.error("verify_register_view: erreur création compte %s : %s", pseudo, e)
        return render(request, 'forms/register.html', {
            'error': "Erreur lors de la création du compte. Veuillez réessayer.",
        })
    finally:
        for k in ('verif_code_register', 'verif_expires_register', 'pending_register'):
            request.session.pop(k, None)

    response = HttpResponse()
    response['HX-Redirect'] = reverse('accounts:login')
    return response


# Fonction pour la connexion dans notre application
def login_view(request):
    if request.method == "POST":
        pseudo = request.POST.get('username')
        mdp    = request.POST.get('password')

        keystone_token = token_verification(pseudo, mdp)

        if keystone_token:
            try:
                user = Utilisateur.objects.get(username=pseudo)
                login(request, user)
                request.session['keystone_token'] = keystone_token
                response = HttpResponse()
                response['HX-Redirect'] = reverse('apps_manager:dashboard')
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
        if response.status_code == 204:
            logger.info("supprimer_utilisateur_keystone: utilisateur %s supprimé", user_keystone_id)
            return True
        else:
            logger.error(
                "supprimer_utilisateur_keystone: erreur Keystone %s — %s",
                response.status_code, response.text,
            )
            return False
    except requests.exceptions.RequestException as e:
        logger.error("supprimer_utilisateur_keystone: erreur de connexion: %s", e)
        return False


# Fonction pour supprimer son compte utilisateur de BarbiLink
@login_required
def supprimer_compte_view(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        user     = request.user

        if not user.check_password(password):
            return render(request, 'forms/confirm_supp_partiel.html', {
                "error": "Mot de passe incorrect.",
                "form_data": request.POST
            })

        try:
            admin_token      = get_admin_token()
            id_ks_user       = user.id_keystone
            keystone_deleted = supprimer_utilisateur_keystone(admin_token, id_ks_user)

            if keystone_deleted:
                user.delete()
                logger.info("supprimer_compte_view: compte et accès Keystone supprimés")
                logout(request)
                response = HttpResponse()
                response['HX-Redirect'] = reverse('accounts:login')
                return response
            else:
                logger.error("supprimer_compte_view: échec de la suppression Keystone")
                return render(request, 'forms/confirm_supp_partiel.html', {
                    "error": "Veuillez reessayer plus tard !",
                    "form_data": request.POST
                })
        except Exception as e:
            logger.critical("supprimer_compte_view: erreur critique: %s", e)
            return render(request, 'forms/confirm_supp_partiel.html', {
                "error": "Veuillez reessayer plus tard !",
                "form_data": request.POST
            })

    return render(request, 'forms/confirm_suppression.html')


# Fonction pour mettre à jour un utilisateur dans Keystone
def modifier_utilisateur_keystone(admin_token, user_id, name=None, password=None, email=None):
    url = f"{settings.KEYSTONE_URL}/users/{user_id}"
    headers = {
        "X-Auth-Token": admin_token,
        "Content-Type": "application/json"
    }

    user_data = {}
    if name:     user_data['name']     = name
    if password: user_data['password'] = password
    if email:    user_data['email']    = email

    payload = {"user": user_data}
    logger.debug("modifier_utilisateur_keystone: payload=%s", payload)

    try:
        response = requests.patch(url, json=payload, headers=headers)
        if response.status_code == 200:
            return True
        else:
            logger.error(
                "modifier_utilisateur_keystone: erreur Keystone %s — %s",
                response.status_code, response.text,
            )
            return False
    except requests.exceptions.RequestException as e:
        logger.error("modifier_utilisateur_keystone: erreur de connexion: %s", e)
        return False


# Fonction pour modifier l'identite de l'utilisateur (étape 1 : envoi du code)
@login_required
def change_identity_view(request):
    if request.method == 'POST':
        user = request.user
        code    = _generer_code_verif()
        expires = time.time() + 600  # 10 minutes

        request.session['verif_code_identite']    = code
        request.session['verif_expires_identite'] = expires
        request.session['pending_identite'] = {
            'first_name': request.POST.get('first_name', '').strip(),
            'last_name':  request.POST.get('last_name',  '').strip(),
            'username':   request.POST.get('username',   '').strip(),
            'email':      request.POST.get('email',      '').strip(),
        }

        _envoyer_code_verif(user, code, 'identite')
        logger.info("change_identity_view: code de vérification envoyé à %s", user.email)

        return render(request, 'accounts/section_verify_code.html', {
            'user_email':  user.email,
            'verify_url':  reverse('accounts:verify_identite'),
            'cancel_url':  reverse('accounts:change_identite'),
            'section_id':  'profile-section',
        })

    return render(request, 'accounts/section_identite.html', {'user': request.user})


# Fonction pour vérifier le code et appliquer les changements d'identité (étape 2)
@login_required
def verify_identity_view(request):
    if request.method == 'POST':
        user       = request.user
        code_saisi = request.POST.get('verif_code', '').strip()
        code_stock = request.session.get('verif_code_identite')
        expires    = request.session.get('verif_expires_identite', 0)
        pending    = request.session.get('pending_identite', {})

        ctx_erreur = {
            'verify_url': reverse('accounts:verify_identite'),
            'cancel_url': reverse('accounts:change_identite'),
            'section_id': 'profile-section',
            'user_email': user.email,
        }

        if not code_stock:
            return render(request, 'accounts/section_verify_code.html', {
                **ctx_erreur, 'error': 'Session expirée. Veuillez recommencer.'
            })

        if time.time() > expires:
            for k in ('verif_code_identite', 'verif_expires_identite', 'pending_identite'):
                request.session.pop(k, None)
            return render(request, 'accounts/section_verify_code.html', {
                **ctx_erreur, 'error': 'Code expiré (10 min). Veuillez recommencer.'
            })

        if code_saisi != code_stock:
            return render(request, 'accounts/section_verify_code.html', {
                **ctx_erreur, 'error': 'Code incorrect. Vérifiez votre boîte mail.'
            })

        # Code valide — appliquer les changements
        first_name = pending.get('first_name')
        last_name  = pending.get('last_name')
        username   = pending.get('username')
        email      = pending.get('email')
        admin_token = get_admin_token()
        user_id     = user.id_keystone

        if username and username != user.username:
            if not modifier_utilisateur_keystone(admin_token, user_id, name=username):
                logger.error("verify_identity_view: échec mise à jour username Keystone")
                return render(request, 'accounts/section_identite.html', {
                    'user': user, 'error_message': "Veuillez réessayer plus tard !"
                })

        if email and email != user.email:
            if not modifier_utilisateur_keystone(admin_token, user_id, email=email):
                logger.error("verify_identity_view: échec mise à jour email Keystone")
                return render(request, 'accounts/section_identite.html', {
                    'user': user, 'error_message': "Veuillez réessayer plus tard !"
                })

        if first_name: user.first_name = first_name
        if last_name:  user.last_name  = last_name
        if username:   user.username   = username
        if email:      user.email      = email
        user.save()

        for k in ('verif_code_identite', 'verif_expires_identite', 'pending_identite'):
            request.session.pop(k, None)

        logger.info("verify_identity_view: identité modifiée pour %s", user.username)
        return render(request, 'accounts/section_identite.html', {
            'user': user,
            'success_message': "Identité modifiée avec succès !",
        })

    return redirect('accounts:profile')


# Fonction pour modifier le mot de passe (étape 1 : validation + envoi du code)
@login_required
def change_password_view(request):
    if request.method == 'POST':
        user      = request.user
        old_pass  = request.POST.get('old_password')
        new_pass  = request.POST.get('new_password')
        conf_pass = request.POST.get('confirm_password')

        if not user.check_password(old_pass):
            return render(request, 'accounts/section_password.html', {
                'error_message': "Ancien mot de passe incorrect.",
                'form_data': request.POST,
            })

        if not new_pass or new_pass != conf_pass:
            return render(request, 'accounts/section_password.html', {
                'error_message': "Les nouveaux mots de passe ne correspondent pas.",
                'form_data': request.POST,
            })

        code    = _generer_code_verif()
        expires = time.time() + 600  # 10 minutes

        request.session['verif_code_password']    = code
        request.session['verif_expires_password'] = expires
        request.session['pending_password']       = new_pass

        _envoyer_code_verif(user, code, 'password')
        logger.info("change_password_view: code de vérification envoyé à %s", user.email)

        return render(request, 'accounts/section_verify_code.html', {
            'user_email': user.email,
            'verify_url': reverse('accounts:verify_password'),
            'cancel_url': reverse('accounts:change_password'),
            'section_id': 'password-section',
        })

    return render(request, 'accounts/section_password.html', {'user': request.user})


# Fonction pour vérifier le code et appliquer le nouveau mot de passe (étape 2)
@login_required
def verify_password_view(request):
    if request.method == 'POST':
        user       = request.user
        code_saisi = request.POST.get('verif_code', '').strip()
        code_stock = request.session.get('verif_code_password')
        expires    = request.session.get('verif_expires_password', 0)
        new_pass   = request.session.get('pending_password')

        ctx_erreur = {
            'verify_url': reverse('accounts:verify_password'),
            'cancel_url': reverse('accounts:change_password'),
            'section_id': 'password-section',
            'user_email': user.email,
        }

        if not code_stock:
            return render(request, 'accounts/section_verify_code.html', {
                **ctx_erreur, 'error': 'Session expirée. Veuillez recommencer.'
            })

        if time.time() > expires:
            for k in ('verif_code_password', 'verif_expires_password', 'pending_password'):
                request.session.pop(k, None)
            return render(request, 'accounts/section_verify_code.html', {
                **ctx_erreur, 'error': 'Code expiré (10 min). Veuillez recommencer.'
            })

        if code_saisi != code_stock:
            return render(request, 'accounts/section_verify_code.html', {
                **ctx_erreur, 'error': 'Code incorrect. Vérifiez votre boîte mail.'
            })

        # Code valide — appliquer le changement
        admin_token = get_admin_token()
        user_id     = user.id_keystone
        success     = modifier_utilisateur_keystone(admin_token, user_id, password=new_pass)

        if not success:
            logger.error("verify_password_view: échec synchronisation Keystone")
            return render(request, 'accounts/section_password.html', {
                'error_message': "Veuillez réessayer plus tard !"
            })

        user.set_password(new_pass)
        user.save()
        update_session_auth_hash(request, user)

        for k in ('verif_code_password', 'verif_expires_password', 'pending_password'):
            request.session.pop(k, None)

        logger.info("verify_password_view: mot de passe modifié pour %s", user.username)
        return render(request, 'accounts/section_password.html', {
            'success_message': "Mot de passe modifié avec succès !"
        })

    return redirect('accounts:profile')


# Fonction pour changer ou supprimer la photo de profil
@login_required
def change_photo_view(request):
    if request.method == 'POST':
        user = request.user

        if request.POST.get('supprimer_photo'):
            if user.photo_profil:
                user.photo_profil.delete(save=False)
                user.photo_profil = None
                user.save()
            return render(request, 'accounts/section_profil.html', {
                'user': user,
                'success_message_photo': 'Photo de profil supprimée.'
            })

        if request.FILES.get('photo_profil'):
            if user.photo_profil:
                user.photo_profil.delete(save=False)
            user.photo_profil = request.FILES['photo_profil']
            user.save()
            return render(request, 'accounts/section_profil.html', {
                'user': user,
                'success_message_photo': 'Photo de profil mise à jour avec succès !'
            })

    return render(request, 'accounts/section_profil.html', {
        'user': request.user,
        'error_message_photo': 'Aucun fichier sélectionné.'
    })


# Fonction pour recuperer le profile de l'utilisateur connecte
@login_required
def profile_view(request):
    if request.headers.get('HX-Request'):
        return render(request, 'accounts/profile_partiel.html', {'user': request.user})
    return render(request, 'accounts/profile.html', {'user': request.user})
