from unittest.mock import MagicMock, patch

from django.test import Client, TestCase
from django.urls import reverse

from accounts.models import Utilisateur


def make_user(**kwargs):
    defaults = {"username": "tester", "password": "pass", "id_keystone": "ks-001"}
    defaults.update(kwargs)
    return Utilisateur.objects.create_user(**defaults)


# ─────────────────────────────────────────────────────────────
# Protection @login_required sur les vues sensibles (Bug 2)
# ─────────────────────────────────────────────────────────────
class LoginRequiredTests(TestCase):
    """Les 3 vues sensibles doivent rediriger un visiteur non authentifié."""

    def setUp(self):
        self.client = Client()

    def _assert_redirige_vers_login(self, url_name):
        url = reverse(url_name)
        response = self.client.get(url)
        self.assertIn(response.status_code, [301, 302], msg=f"{url_name} doit rediriger")
        self.assertTrue(response["Location"].startswith("/"),
                        msg=f"{url_name} doit pointer vers la page de login")

    def test_ajouter_secret_redirige_sans_auth(self):
        self._assert_redirige_vers_login("secrets_manager:ajouter_secret")

    def test_proposition_secret_redirige_sans_auth(self):
        self._assert_redirige_vers_login("secrets_manager:proposition_secret")

    def test_passer_secret_redirige_sans_auth(self):
        self._assert_redirige_vers_login("secrets_manager:passer_secret")

    def test_ajouter_secret_accessible_connecte(self):
        user = make_user()
        self.client.force_login(user)
        url = reverse("secrets_manager:ajouter_secret")
        response = self.client.get(url)
        # 200 ou redirect interne (pas vers login)
        self.assertNotEqual(response.status_code, 302)


# ─────────────────────────────────────────────────────────────
# Logique _traiter_cle — condition paire corrigée (Bug 3)
# ─────────────────────────────────────────────────────────────
class TraiterCleConditionTests(TestCase):
    """
    Vérifie que la branche 'upload paire' s'active sur
    api_private_key_file / api_public_key_file, pas api_key_file.
    """

    def _bc_mock(self):
        """Construit un mock de client Barbican minimal."""
        container = MagicMock()
        container.secrets.get.side_effect = lambda key: MagicMock(secret_ref=f"ref-{key}")
        bc = MagicMock()
        bc.containers.get.return_value = container
        return bc

    @patch("secrets_manager.utils.stocker_cle_barbican",
           return_value="ref-unique")
    @patch("secrets_manager.utils.stocker_cle_unique_conteneur_barbican",
           return_value="container-unique")
    def test_upload_cle_unique(self, _cont, _store):
        from secrets_manager.utils import _traiter_cle
        result = _traiter_cle(MagicMock(), {
            "api_type":    "unique",
            "secret_name": "ma-cle",
            "api_key_file": b"contenu-cle",
        })
        self.assertEqual(result["type_conteneur"], "generic")
        _store.assert_called_once()

    @patch("secrets_manager.utils.stocker_paire_cles_conteneur_barbican",
           return_value="container-paire")
    def test_upload_paire_avec_cles_fournies(self, mock_paire):
        """Bug 3 : la branche paire doit s'activer avec api_private/public_key_file."""
        from secrets_manager.utils import _traiter_cle
        result = _traiter_cle(self._bc_mock(), {
            "api_type":            "paire",
            "secret_name":         "ma-paire",
            "api_private_key_file": b"private",
            "api_public_key_file":  b"public",
        })
        self.assertEqual(result["type_conteneur"], "rsa")
        mock_paire.assert_called_once()

    @patch("secrets_manager.utils.stocker_paire_cles_conteneur_barbican",
           return_value="container-paire")
    def test_upload_paire_avec_cle_privee_seule(self, mock_paire):
        """La branche paire doit s'activer même avec une seule clé fournie."""
        from secrets_manager.utils import _traiter_cle
        result = _traiter_cle(self._bc_mock(), {
            "api_type":            "paire",
            "secret_name":         "paire-partielle",
            "api_private_key_file": b"private",
        })
        self.assertEqual(result["type_conteneur"], "rsa")
        mock_paire.assert_called_once()

    @patch("secrets_manager.utils.generer_cle_asymetrique",
           return_value="container-gen")
    def test_generation_paire_sans_fichier(self, mock_gen):
        """Quand aucun fichier n'est fourni, la paire doit être générée."""
        from secrets_manager.utils import _traiter_cle
        result = _traiter_cle(self._bc_mock(), {
            "api_type":    "paire",
            "secret_name": "paire-gen",
        })
        self.assertEqual(result["type_conteneur"], "rsa")
        mock_gen.assert_called_once()

    @patch("secrets_manager.utils.generer_cle_symetrique",
           return_value="ref-gen")
    @patch("secrets_manager.utils.stocker_cle_unique_conteneur_barbican",
           return_value="container-gen-unique")
    def test_generation_unique_sans_fichier(self, _cont, _gen):
        """Quand api_key_file est absent pour type unique, la clé doit être générée."""
        from secrets_manager.utils import _traiter_cle
        result = _traiter_cle(MagicMock(), {
            "api_type":    "unique",
            "secret_name": "gen-unique",
        })
        self.assertEqual(result["type_conteneur"], "generic")
        _gen.assert_called_once()
