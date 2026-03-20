"""
Tests pour l'app api_manager.
Couvre :
  - Modèle TokenAcces (génération, unicité, renouvellement)
  - Vue generer_token_view
  - Vue renouveler_token_view
  - Vue api_lire_secret_view (auth, accès wrong secret, dispatch par type)
  - Service notifications (envoi email)
"""
from unittest.mock import patch, MagicMock

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone

from apps_manager.models import Application, Projet
from secrets_manager.models import ConteneurSecret, Secret
from api_manager.models import TokenAcces

User = get_user_model()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_user(username='alice', password='Pass1234!'):
    return User.objects.create_user(
        username=username,
        password=password,
        email=f'{username}@test.com',
        id_keystone=f'ks-{username}',
    )


def make_app_projet(user, nom='MonApp'):
    app = Application.objects.create(
        id_app=f'app-id-{nom}',
        nom_app=nom,
        password_app='secret',
    )
    projet = Projet.objects.create(
        id_projet=f'proj-{nom}',
        nom_projet=f'projet_{nom}',
        application=app,
        utilisateur=user,
    )
    return app, projet


def make_conteneur(projet, nom='cle-api', type_cont='generic'):
    return ConteneurSecret.objects.create(
        projet=projet,
        nom_conteneur=nom,
        type_conteneur=type_cont,
        date_expiration=timezone.now() + timezone.timedelta(days=365),
        ref_old_conteneur=f'http://barbican/containers/{nom}',
        duree_validite=365,
    )


def make_secret(conteneur, nom='sym-key', type_s='symmetric', ref='http://barbican/secrets/1'):
    return Secret.objects.create(
        conteneur=conteneur,
        nom_secret=nom,
        type_secret=type_s,
        ref_secret=ref,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tests modèle TokenAcces
# ─────────────────────────────────────────────────────────────────────────────

class TokenAccesModelTests(TestCase):

    def setUp(self):
        self.user = make_user()
        _, self.projet = make_app_projet(self.user)
        self.conteneur = make_conteneur(self.projet)

    def test_generer_cree_un_token(self):
        token_obj = TokenAcces.generer(self.conteneur)
        self.assertIsNotNone(token_obj.token)
        self.assertEqual(len(token_obj.token), 64)

    def test_generer_deux_fois_renouvelle(self):
        t1 = TokenAcces.generer(self.conteneur)
        val1 = t1.token
        t2 = TokenAcces.generer(self.conteneur)
        val2 = t2.token
        # Même objet (OneToOne), token renouvelé
        self.assertEqual(t1.pk, t2.pk)
        self.assertNotEqual(val1, val2)

    def test_token_unique(self):
        t1 = TokenAcces.generer(self.conteneur)
        # Un second conteneur doit avoir un token différent
        conteneur2 = make_conteneur(self.projet, nom='cle-api-2')
        t2 = TokenAcces.generer(conteneur2)
        self.assertNotEqual(t1.token, t2.token)


# ─────────────────────────────────────────────────────────────────────────────
# Tests vue generer_token_view
# ─────────────────────────────────────────────────────────────────────────────

class GenererTokenViewTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        _, self.projet = make_app_projet(self.user)
        self.conteneur = make_conteneur(self.projet)
        self.url = reverse('api_manager:generer_token')

    def test_non_authentifie_redirige(self):
        r = self.client.post(self.url, {'conteneur_id': self.conteneur.id})
        self.assertEqual(r.status_code, 302)

    @patch('api_manager.views.notifier_token_genere')
    def test_authentifie_cree_token(self, mock_notif):
        self.client.force_login(self.user)
        r = self.client.post(self.url, {'conteneur_id': self.conteneur.id})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn('token', data)
        self.assertEqual(len(data['token']), 64)
        mock_notif.assert_called_once()

    def test_conteneur_autre_utilisateur_404(self):
        autre = make_user('bob')
        self.client.force_login(autre)
        r = self.client.post(self.url, {'conteneur_id': self.conteneur.id})
        self.assertEqual(r.status_code, 404)


# ─────────────────────────────────────────────────────────────────────────────
# Tests vue renouveler_token_view
# ─────────────────────────────────────────────────────────────────────────────

class RenouvelerTokenViewTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        _, self.projet = make_app_projet(self.user)
        self.conteneur = make_conteneur(self.projet)
        TokenAcces.generer(self.conteneur)
        self.url = reverse('api_manager:renouveler_token')

    @patch('api_manager.views.notifier_token_renouvele')
    def test_renouveler_change_token(self, mock_notif):
        ancien_token = TokenAcces.objects.get(conteneur=self.conteneur).token
        self.client.force_login(self.user)
        r = self.client.post(self.url, {'conteneur_id': self.conteneur.id})
        self.assertEqual(r.status_code, 200)
        nouveau_token = r.json()['token']
        self.assertNotEqual(ancien_token, nouveau_token)
        mock_notif.assert_called_once()


# ─────────────────────────────────────────────────────────────────────────────
# Tests vue api_lire_secret_view
# ─────────────────────────────────────────────────────────────────────────────

class ApiLireSecretViewTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = make_user()
        _, self.projet = make_app_projet(self.user)
        self.conteneur = make_conteneur(self.projet, nom='ma-cle', type_cont='generic')
        make_secret(self.conteneur)
        self.token_obj = TokenAcces.generer(self.conteneur)
        self.url = reverse('api_manager:lire_secret', kwargs={'nom_secret': 'ma-cle'})

    def test_sans_token_401(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 401)

    def test_mauvais_token_401(self):
        r = self.client.get(self.url, HTTP_AUTHORIZATION='Bearer invalid-token')
        self.assertEqual(r.status_code, 401)
        self.assertIn('révoqué', r.json()['erreur'])

    def test_token_mauvais_secret_403(self):
        url_autre = reverse('api_manager:lire_secret', kwargs={'nom_secret': 'autre-secret'})
        r = self.client.get(url_autre, HTTP_AUTHORIZATION=f'Bearer {self.token_obj.token}')
        self.assertEqual(r.status_code, 403)

    def test_method_post_405(self):
        r = self.client.post(self.url, HTTP_AUTHORIZATION=f'Bearer {self.token_obj.token}')
        self.assertEqual(r.status_code, 405)

    @patch('api_manager.views._get_admin_barbican_client')
    @patch('api_manager.views.notifier_acces_api')
    def test_generic_retourne_valeur(self, mock_notif, mock_bc):
        mock_secret = MagicMock()
        mock_secret.payload = b'ma-valeur-secrete'
        mock_bc.return_value.secrets.get.return_value = mock_secret

        r = self.client.get(self.url, HTTP_AUTHORIZATION=f'Bearer {self.token_obj.token}')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data['valeur'], 'ma-valeur-secrete')
        self.assertEqual(data['type'], 'generic')
        mock_notif.assert_called_once()

    @patch('api_manager.views._get_admin_barbican_client')
    @patch('api_manager.views.notifier_acces_api')
    def test_barbican_connexion_echouee_503(self, mock_notif, mock_bc):
        from secrets_manager.fonctions import BarbicanConnectionError
        mock_bc.side_effect = BarbicanConnectionError("down")
        r = self.client.get(self.url, HTTP_AUTHORIZATION=f'Bearer {self.token_obj.token}')
        self.assertEqual(r.status_code, 503)

    @patch('api_manager.views._get_admin_barbican_client')
    @patch('api_manager.views.notifier_acces_api')
    def test_rsa_public_retourne_valeur(self, mock_notif, mock_bc):
        conteneur_rsa = make_conteneur(self.projet, nom='ma-paire', type_cont='rsa')
        make_secret(conteneur_rsa, nom='public-key', type_s='public',
                    ref='http://barbican/secrets/pub')
        token_rsa = TokenAcces.generer(conteneur_rsa)

        mock_secret = MagicMock()
        mock_secret.payload = b'-----BEGIN PUBLIC KEY-----'
        mock_bc.return_value.secrets.get.return_value = mock_secret

        url = reverse('api_manager:lire_secret', kwargs={'nom_secret': 'ma-paire'})
        r = self.client.get(url + '?type=public',
                            HTTP_AUTHORIZATION=f'Bearer {token_rsa.token}')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['type'], 'rsa_public')


# ─────────────────────────────────────────────────────────────────────────────
# Tests service de notifications
# ─────────────────────────────────────────────────────────────────────────────

class NotificationsServiceTests(TestCase):

    def setUp(self):
        self.user = make_user('charlie')

    @patch('api_manager.notifications.send_mail')
    def test_notifier_inscription(self, mock_send):
        from api_manager.notifications import notifier_inscription
        notifier_inscription(self.user)
        mock_send.assert_called_once()
        sujet = mock_send.call_args[1]['subject']
        self.assertIn('Bienvenue', sujet)

    @patch('api_manager.notifications.send_mail')
    def test_notifier_app_creee(self, mock_send):
        from api_manager.notifications import notifier_app_creee
        notifier_app_creee(self.user, 'MonApp')
        mock_send.assert_called_once()
        self.assertIn('MonApp', mock_send.call_args[1]['subject'])

    @patch('api_manager.notifications.send_mail')
    def test_notifier_secret_renouvele_mode(self, mock_send):
        from api_manager.notifications import notifier_secret_renouvele
        notifier_secret_renouvele(self.user, 'cle-api', 'projet_app', mode='auto')
        corps = mock_send.call_args[1]['message']
        self.assertIn('automatiquement', corps)

    @patch('api_manager.notifications.send_mail')
    def test_erreur_envoi_absorbee(self, mock_send):
        """Une exception dans send_mail ne doit pas se propager."""
        from api_manager.notifications import notifier_inscription
        mock_send.side_effect = Exception("SMTP down")
        # Ne doit pas lever
        notifier_inscription(self.user)
