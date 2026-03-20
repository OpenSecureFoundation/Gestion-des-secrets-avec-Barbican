from django.urls import path
from . import views

app_name = 'api_manager'

urlpatterns = [
    # --- Interface utilisateur (protégée par login) ---
    path('token/generer/',   views.generer_token_view,   name='generer_token'),
    path('token/renouveler/', views.renouveler_token_view, name='renouveler_token'),

    # --- API publique tierce (authentification par Bearer token) ---
    path('v1/secrets/<str:nom_secret>/', views.api_lire_secret_view, name='lire_secret'),
]
