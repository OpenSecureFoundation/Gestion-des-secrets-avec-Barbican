from io import BytesIO
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from accounts.models import Utilisateur


def make_user(**kwargs):
    defaults = {
        "username":    "testuser",
        "password":    "TestPass123!",
        "email":       "test@example.com",
        "id_keystone": "ks-uuid-001",
    }
    defaults.update(kwargs)
    return Utilisateur.objects.create_user(**defaults)


# ─────────────────────────────────────────────────────────────
# Connexion
# ─────────────────────────────────────────────────────────────
class LoginViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("accounts:login")

    def test_get_renders_form(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "forms/login.html")

    @patch("accounts.views.token_verification", return_value=None)
    def test_identifiants_invalides_affiche_erreur(self, _mock):
        response = self.client.post(self.url, {"username": "bad", "password": "bad"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Identifiants invalides")

    @patch("accounts.views.token_verification", return_value="fake-token")
    def test_utilisateur_inconnu_affiche_erreur(self, _mock):
        # Keystone OK mais utilisateur absent de la DB locale
        response = self.client.post(self.url, {"username": "ghost", "password": "pass"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Identifiants invalides")

    @patch("accounts.views.token_verification", return_value="fake-token")
    def test_connexion_valide_renvoie_hx_redirect(self, _mock):
        make_user()
        response = self.client.post(
            self.url,
            {"username": "testuser", "password": "TestPass123!"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("HX-Redirect", response)


# ─────────────────────────────────────────────────────────────
# Inscription
# ─────────────────────────────────────────────────────────────
class RegisterViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("accounts:register")

    def test_get_renders_form(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "forms/register.html")

    def test_mots_de_passe_differents_affiche_erreur(self):
        response = self.client.post(self.url, {
            "first_name":       "Alice",
            "last_name":        "Dupont",
            "username":         "alice",
            "email":            "alice@example.com",
            "password":         "pass1",
            "confirm_password": "pass2",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Mots de passe")

    @patch("accounts.views.creer_utilisateur_keystone", return_value=None)
    def test_echec_keystone_affiche_erreur(self, _mock):
        response = self.client.post(self.url, {
            "first_name":       "Eve",
            "last_name":        "Smith",
            "username":         "evesmith",
            "email":            "eve@example.com",
            "password":         "pass",
            "confirm_password": "pass",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Données invalides")

    @patch("accounts.views.creer_utilisateur_keystone", return_value="ks-new-uuid")
    def test_inscription_valide_cree_utilisateur(self, _mock):
        response = self.client.post(self.url, {
            "first_name":       "Bob",
            "last_name":        "Martin",
            "username":         "bobmartin",
            "email":            "bob@example.com",
            "password":         "SecurePass1!",
            "confirm_password": "SecurePass1!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("HX-Redirect", response)
        self.assertTrue(Utilisateur.objects.filter(username="bobmartin").exists())


# ─────────────────────────────────────────────────────────────
# Profil
# ─────────────────────────────────────────────────────────────
class ProfileViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user   = make_user()
        self.url    = reverse("accounts:profile")

    def test_redirige_non_authentifie(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, [301, 302])
        self.assertTrue(response["Location"].startswith("/"))

    def test_page_complete_pour_utilisateur_connecte(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/profile.html")

    def test_htmx_retourne_partiel(self):
        self.client.force_login(self.user)
        response = self.client.get(self.url, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/profile_partiel.html")


# ─────────────────────────────────────────────────────────────
# Changement de mot de passe
# ─────────────────────────────────────────────────────────────
class ChangePasswordViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user   = make_user()
        self.client.force_login(self.user)
        self.url = reverse("accounts:change_password")

    def test_ancien_mot_de_passe_incorrect(self):
        response = self.client.post(self.url, {
            "old_password":     "mauvais",
            "new_password":     "NewPass1!",
            "confirm_password": "NewPass1!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "incorrect")

    def test_nouveaux_mots_de_passe_differents(self):
        response = self.client.post(self.url, {
            "old_password":     "TestPass123!",
            "new_password":     "NewPass1!",
            "confirm_password": "Autre!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "correspondent pas")

    @patch("accounts.views.modifier_utilisateur_keystone", return_value=True)
    @patch("accounts.views.get_admin_token", return_value="admin-token")
    def test_changement_valide_affiche_succes(self, _tok, _mod):
        response = self.client.post(self.url, {
            "old_password":     "TestPass123!",
            "new_password":     "NewSecure99!",
            "confirm_password": "NewSecure99!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "succès")

    @patch("accounts.views.modifier_utilisateur_keystone", return_value=False)
    @patch("accounts.views.get_admin_token", return_value="admin-token")
    def test_erreur_keystone_affiche_message(self, _tok, _mod):
        response = self.client.post(self.url, {
            "old_password":     "TestPass123!",
            "new_password":     "NewSecure99!",
            "confirm_password": "NewSecure99!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "reessayer")


# ─────────────────────────────────────────────────────────────
# Photo de profil
# ─────────────────────────────────────────────────────────────
class ChangePhotoViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user   = make_user()
        self.client.force_login(self.user)
        self.url = reverse("accounts:change_photo")

    def test_sans_fichier_affiche_erreur(self):
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Aucun fichier")

    def test_supprimer_photo_inexistante_ne_plante_pas(self):
        response = self.client.post(self.url, {"supprimer_photo": "1"})
        self.assertEqual(response.status_code, 200)

    def test_upload_photo_valide(self):
        # PNG 1×1 pixel minimal
        png_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
            b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18"
            b"\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        photo = SimpleUploadedFile("avatar.png", png_bytes, content_type="image/png")
        response = self.client.post(self.url, {"photo_profil": photo})
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(bool(self.user.photo_profil))
        # Nettoyage du fichier uploadé
        self.user.photo_profil.delete(save=False)

    def test_supprimer_photo_existante(self):
        # Upload d'abord
        png_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
            b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18"
            b"\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        photo = SimpleUploadedFile("avatar2.png", png_bytes, content_type="image/png")
        self.client.post(self.url, {"photo_profil": photo})
        # Puis suppression
        response = self.client.post(self.url, {"supprimer_photo": "1"})
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(bool(self.user.photo_profil))
