from django.urls import path
from . import views

app_name = 'secrets_manager'

urlpatterns = [
    path("new_secret/", views.ajouter_secret_view, name="ajouter_secret"),
    path("renew_secret/", views.renouveler_secret_view, name="renouveler_secret"),
    path("proposition-secret/", views.proposition_secret_view, name="proposition_secret"),
    path("proposition-secret/passer/", views.passer_secret_view, name="passer_secret"),
]