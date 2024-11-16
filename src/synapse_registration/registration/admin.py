from django.contrib import admin

from .models import UserRegistration


@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "email_verified", "status", "ip_address")
    list_filter = ("status", "email_verified")
    search_fields = ("username", "email", "ip_address")
    actions = ["approve_registrations", "deny_registrations"]

    def approve_registrations(self, request, queryset):
        queryset.update(status=UserRegistration.STATUS_APPROVED)
        self.message_user(request, f"{queryset.count()} registrations approved.")

    def deny_registrations(self, request, queryset):
        queryset.update(status=UserRegistration.STATUS_DENIED)
        self.message_user(request, f"{queryset.count()} registrations denied.")

    approve_registrations.short_description = "Approve selected registrations"
    deny_registrations.short_description = "Deny selected registrations"
