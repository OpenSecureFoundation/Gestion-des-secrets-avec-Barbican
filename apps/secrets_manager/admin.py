from django.contrib import admin

from secrets_manager.models import ConteneurSecret, Secret

# Register your models here.
admin.site.register(ConteneurSecret)
admin.site.register(Secret)