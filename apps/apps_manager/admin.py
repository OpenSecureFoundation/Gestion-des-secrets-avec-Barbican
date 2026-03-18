from django.contrib import admin

from apps_manager.models import Application, Projet

# Register your models here.
admin.site.register(Projet)
admin.site.register(Application)