from django.contrib import admin
from django.contrib.auth.models import Group

from .models import UserRegistration, EmailBlock, IPBlock, UsernameRule

admin.site.site_header = "Synapse Registration Administration"
admin.site.site_title = "Synapse Registration Administration"
admin.site.index_title = "Welcome to the Synapse Registration Administration"

admin.site.register(EmailBlock)
admin.site.register(IPBlock)
admin.site.register(UsernameRule)

admin.site.unregister(Group)


@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "email_verified_symbol", "status_symbol", "timestamp", "ip_address")
    list_filter = ("status", "email_verified")
    search_fields = ("username", "email", "ip_address")
    actions = ["approve_registrations", "deny_registrations"]

    def email_verified_symbol(self, obj):
        return "✅" if obj.email_verified else "❌"

    def status_symbol(self, obj):
        if obj.status == UserRegistration.STATUS_APPROVED:
            return "✅"
        elif obj.status == UserRegistration.STATUS_DENIED:
            return "❌"
        else:
            return f"⌛ ({obj.get_status_display()})"

    email_verified_symbol.short_description = "Email verified"
    status_symbol.short_description = "Status"

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
