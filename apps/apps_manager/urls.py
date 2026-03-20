from django.urls import path
from . import views

app_name = 'apps_manager'

urlpatterns = [
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('', views.list_apps_view, name='list_app'),
    path('new_app/', views.creer_app_view, name='creer_app'),
    path('delete_app/', views.supprimer_app_view, name='supprimer_app'),
    path('edit_app/', views.modifier_app_view, name='modifier_app'),
    path('detail_app/', views.detail_app_view, name='detail_app'),
    path('edit_conteneur/', views.modifier_conteneur_view, name='modifier_conteneur'),
    path('delete_conteneur/', views.supprimer_conteneur_view, name='supprimer_conteneur'),
    path('delete_apps_selection/', views.supprimer_apps_selection_view, name='supprimer_apps_selection'),
    path('delete_conteneurs_selection/', views.supprimer_conteneurs_selection_view, name='supprimer_conteneurs_selection'),
    path('search/', views.recherche_view, name='recherche'),
]