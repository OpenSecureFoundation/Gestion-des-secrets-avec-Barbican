"""
URL configuration for BarbiLink project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path, re_path
from django.views.static import serve
from BarbiLink import settings


def handler404_view(request, exception=None):
    return render(request, '404.html', status=404)


handler404 = handler404_view

urlpatterns = [
    path('admin/', admin.site.urls),

    ######## Nouveaux ajouts #########
    path('', include('accounts.urls')),
    path('apps/', include('apps_manager.urls')),
    path('secrets/', include('secrets_manager.urls')),
    path('api/', include('api_manager.urls')),

    # Fichiers statiques et médias servis directement (développement local)
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.BASE_DIR / 'static'}),
    re_path(r'^media/(?P<path>.*)$',  serve, {'document_root': settings.MEDIA_ROOT}),
]