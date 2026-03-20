from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('register/verify/', views.verify_register_view, name='verify_register'),
    path('profile/',views.profile_view, name='profile'),
    path('profile/identite', views.change_identity_view, name='change_identite'),
    path('profile/identite/verify', views.verify_identity_view, name='verify_identite'),
    path('profile/password', views.change_password_view, name='change_password'),
    path('profile/password/verify', views.verify_password_view, name='verify_password'),
    path('logout/',views.logout_view, name='logout'),   
    path('profile/delete_user',views.supprimer_compte_view, name='delete_user'),
    path('profile/photo', views.change_photo_view, name='change_photo'),
]