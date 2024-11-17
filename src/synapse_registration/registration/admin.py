from django.contrib import admin
from django.contrib.auth.models import Group

from .models import UserRegistration

admin.site.site_header = "Synapse Registration Administration"

admin.site.unregister(Group)


@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "email_verified", "status", "ip_address")
    list_filter = ("status", "email_verified")
    search_fields = ("username", "email", "ip_address")
    actions = ["approve_registrations", "deny_registrations"]

    def approve_registrations(self, request, queryset):
        for registration in queryset:
            registration.status = UserRegistration.STATUS_APPROVED
            registration.save()

        self.message_user(request, f"{queryset.count()} registrations approved.")

    def deny_registrations(self, request, queryset):
        for registration in queryset:
            registration.status = UserRegistration.STATUS_DENIED
            registration.save()

        self.message_user(request, f"{queryset.count()} registrations denied.")

    approve_registrations.short_description = "Approve selected registrations"
    deny_registrations.short_description = "Deny selected registrations"
