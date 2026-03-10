from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('profile/',views.profile_view, name='profile'),
    path('profile/identite',views.change_identity_view, name='change_identite'),
    path('profile/password',views.change_password_view, name='change_password'),
    path('logout/',views.logout_view, name='logout'),   
    path('profile/delete_user',views.supprimer_compte_view, name='delete_user'), 
]