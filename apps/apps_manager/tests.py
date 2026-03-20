from django.test import Client, TestCase
from django.urls import reverse

from accounts.models import Utilisateur


def make_user(**kwargs):
    defaults = {"username": "mgr", "password": "pass", "id_keystone": "ks-mgr-001"}
    defaults.update(kwargs)
    return Utilisateur.objects.create_user(**defaults)


# ─────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────
class DashboardViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("apps_manager:dashboard")

    def test_redirige_non_authentifie(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, [301, 302])
        self.assertTrue(response["Location"].startswith("/"))

    def test_accessible_connecte(self):
        self.client.force_login(make_user())
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

    def test_tri_par_date_asc(self):
        self.client.force_login(make_user())
        response = self.client.get(self.url + "?sort=date_asc")
        self.assertEqual(response.status_code, 200)

    def test_tri_par_date_desc(self):
        self.client.force_login(make_user())
        response = self.client.get(self.url + "?sort=date_desc")
        self.assertEqual(response.status_code, 200)

    def test_tri_invalide_ne_plante_pas(self):
        self.client.force_login(make_user())
        response = self.client.get(self.url + "?sort=inexistant")
        self.assertEqual(response.status_code, 200)


# ─────────────────────────────────────────────────────────────
# Liste des applications
# ─────────────────────────────────────────────────────────────
class ListAppViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("apps_manager:list_app")

    def test_redirige_non_authentifie(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, [301, 302])
        self.assertTrue(response["Location"].startswith("/"))

    def test_accessible_connecte(self):
        self.client.force_login(make_user())
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)


# ─────────────────────────────────────────────────────────────
# Création d'application
# ─────────────────────────────────────────────────────────────
class CreerAppViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("apps_manager:creer_app")

    def test_redirige_non_authentifie(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, [301, 302])

    def test_get_accessible_connecte(self):
        self.client.force_login(make_user())
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
