from django.contrib import admin
from django.contrib.auth.models import Group
from django.utils.html import format_html

from .models import UserRegistration, EmailBlock, IPBlock, UsernameRule

admin.site.site_header = "Synapse Registration Administration"
admin.site.site_title = "Synapse Registration Administration"
admin.site.index_title = "Welcome to the Synapse Registration Administration"

admin.site.unregister(Group)


@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = (
        "username",
        "email",
        "email_verified_symbol",
        "status_symbol",
        "timestamp",
        "ip_address",
    )
    list_filter = ("status", "email_verified", "timestamp")
    search_fields = ("username", "email", "ip_address", "registration_reason")
    actions = ["approve_registrations", "deny_registrations"]
    readonly_fields = ("timestamp", "ip_address", "token")
    fieldsets = (
        ("User Information", {
            "fields": ("username", "email", "email_verified", "status")
        }),
        ("Registration Details", {
            "fields": ("registration_reason", "ip_address", "timestamp")
        }),
        ("Moderation", {
            "fields": ("mod_message", "notify")
        }),
        ("Technical Details", {
            "classes": ("collapse",),
            "fields": ("token",),
        }),
    )

    def email_verified_symbol(self, obj):
        return "✅" if obj.email_verified else "❌"

    def status_symbol(self, obj):
        if obj.status == UserRegistration.STATUS_APPROVED:
            return format_html('<span style="color: green; font-weight: bold;">✅ Approved</span>')
        elif obj.status == UserRegistration.STATUS_DENIED:
            return format_html('<span style="color: red; font-weight: bold;">❌ Denied</span>')
        elif obj.status == UserRegistration.STATUS_REQUESTED:
            return format_html('<span style="color: orange; font-weight: bold;">⏳ Requested</span>')
        elif obj.status == UserRegistration.STATUS_COMPLETED:
            return format_html('<span style="color: blue; font-weight: bold;">✅ Completed</span>')
        else:
            return format_html('<span style="color: gray; font-weight: bold;">🔄 Started</span>')

    email_verified_symbol.short_description = "Email verified"
    status_symbol.short_description = "Status"
    status_symbol.allow_tags = True

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


admin.site.register(EmailBlock)
admin.site.register(IPBlock)
admin.site.register(UsernameRule)

# Monkey patching to ensure the registration app is always displayed first in the admin panel

admin.AdminSite._get_app_list = admin.AdminSite.get_app_list


def get_app_list(self, request, app_label=None):
    """
    Ensures that the registration app is always displayed first in the admin panel.
    """
    app_list = admin.AdminSite._get_app_list(self, request, app_label)
    if app_list:
        app_list.sort(key=lambda x: x["app_label"] != "registration")  # False < True
        app_list[0]["models"].sort(key=lambda x: x["object_name"] != "UserRegistration")
        
    return app_list


admin.AdminSite.get_app_list = get_app_list
