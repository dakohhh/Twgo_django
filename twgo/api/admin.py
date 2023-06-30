from django.contrib import admin

from . import models


class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "first_name", "last_name", "email")


admin.site.register(models.User)
admin.site.register(models.Project)
admin.site.register(models.Funds)
admin.site.register(models.Message)
admin.site.register(models.Conversation)
