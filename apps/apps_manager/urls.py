from django.urls import path
from . import views

app_name = 'apps_manager'

urlpatterns = [
    path('', views.list_apps_view, name='list_app'),
    path('new_app/', views.creer_app_view, name='creer_app'),
    path('delete_app/', views.supprimer_app_view, name='supprimer_app'),    
]