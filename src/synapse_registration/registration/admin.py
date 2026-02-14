from django.contrib import admin, messages
from django.contrib.auth.models import Group
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

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
        "registration_reason",
        "status_badge",
        "timestamp",
        "ip_address",
        "actions_column",
    )
    list_filter = ("status", "email_verified", "timestamp")
    search_fields = ("username", "email", "ip_address", "registration_reason")
    ordering = ("-timestamp",)

    # Prevent “edit everything” behavior
    readonly_fields = (
        "username",
        "email",
        "email_verified",
        "status",
        "registration_reason",
        "ip_address",
        "timestamp",
        "token",
    )
    fieldsets = (
        (
            "User Information",
            {"fields": ("username", "email", "email_verified", "status")},
        ),
        (
            "Registration Details",
            {"fields": ("registration_reason", "ip_address", "timestamp")},
        ),
        ("Moderation Response", {"fields": ("mod_message", "notify")}),
        ("Technical Details", {"classes": ("collapse",), "fields": ("token",)}),
    )

    # Disable bulk actions that can bypass workflows
    actions = None

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        return False

    def get_readonly_fields(self, request: HttpRequest, obj=None):
        ro = list(super().get_readonly_fields(request, obj))
        if obj and obj.status in (UserRegistration.STATUS_COMPLETED,):
            ro += ["mod_message", "notify"]
        return ro

    @admin.display(description="Email verified")
    def email_verified_symbol(self, obj: UserRegistration) -> str:
        return "✅" if obj.email_verified else "❌"

    @admin.display(description="Status")
    def status_badge(self, obj: UserRegistration) -> str:
        if obj.status == UserRegistration.STATUS_APPROVED:
            return mark_safe('<b style="color: #0a7;">✅ Approved</b>')
        if obj.status == UserRegistration.STATUS_DENIED:
            return mark_safe('<b style="color: #c00;">❌ Denied</b>')
        if obj.status == UserRegistration.STATUS_REQUESTED:
            return mark_safe('<b style="color: #c60;">⏳ Requested</b>')
        if obj.status == UserRegistration.STATUS_COMPLETED:
            return mark_safe('<b style="color: #06c;">✅ Completed</b>')
        return mark_safe('<b style="color: #666;">🔄 Started</b>')

    @admin.display(description="Actions")
    def actions_column(self, obj: UserRegistration) -> str:
        approve_url = reverse(
            "admin:registration_userregistration_approve", args=[obj.pk]
        )
        deny_url = reverse("admin:registration_userregistration_deny", args=[obj.pk])

        # Only show buttons when it makes sense
        if obj.status != UserRegistration.STATUS_REQUESTED:
            return "—"

        return format_html(
            '<a class="button" style=" background:#0a7;color:#fff;margin-right:5px" href="{}">Approve</a>'
            '<a class="button" style="background:#c00;color:#fff" href="{}">Deny</a>',
            approve_url,
            deny_url,
        )

    def get_urls(self):
        urls = super().get_urls()
        custom = [
            path(
                "<path:object_id>/approve/",
                self.admin_site.admin_view(self.approve_view),
                name="registration_userregistration_approve",
            ),
            path(
                "<path:object_id>/deny/",
                self.admin_site.admin_view(self.deny_view),
                name="registration_userregistration_deny",
            ),
        ]
        return custom + urls

    def _transition_allowed(self, obj: UserRegistration) -> bool:
        return obj.status == UserRegistration.STATUS_REQUESTED and obj.email_verified

    def approve_view(self, request: HttpRequest, object_id: str) -> HttpResponse:
        obj = get_object_or_404(UserRegistration, pk=object_id)

        if not self._transition_allowed(obj):
            self.message_user(
                request,
                "This registration cannot be approved in its current state.",
                level=messages.ERROR,
            )
            return redirect(f"../{object_id}/change/")

        if request.method == "POST":
            obj.mod_message = request.POST.get("mod_message", obj.mod_message or "")
            obj.notify = request.POST.get("notify") == "on"

            obj.status = UserRegistration.STATUS_APPROVED
            obj.save()

            # TODO: audit trail hook, e.g. create event "approved" with actor=request.user
            self.message_user(
                request,
                f"Approved registration for {obj.username}.",
                level=messages.SUCCESS,
            )
            return redirect(f"../{object_id}/change/")

        context = {
            **self.admin_site.each_context(request),
            "opts": self.model._meta,
            "original": obj,
            "title": f"Approve registration: {obj.username}",
            "action_name": "approve",
        }
        return TemplateResponse(
            request, "admin/registration/userregistration/confirm_action.html", context
        )

    def deny_view(self, request: HttpRequest, object_id: str) -> HttpResponse:
        obj = get_object_or_404(UserRegistration, pk=object_id)

        if obj.status != UserRegistration.STATUS_REQUESTED:
            self.message_user(
                request,
                "This registration cannot be denied in its current state.",
                level=messages.ERROR,
            )
            return redirect(f"../{object_id}/change/")

        if request.method == "POST":
            obj.mod_message = request.POST.get("mod_message", obj.mod_message or "")
            obj.notify = request.POST.get("notify") == "on"

            obj.status = UserRegistration.STATUS_DENIED
            obj.save()

            # TODO: audit trail hook
            self.message_user(
                request,
                f"Denied registration for {obj.username}.",
                level=messages.SUCCESS,
            )
            return redirect(f"../{object_id}/change/")

        context = {
            **self.admin_site.each_context(request),
            "opts": self.model._meta,
            "original": obj,
            "title": f"Deny registration: {obj.username}",
            "action_name": "deny",
        }
        return TemplateResponse(
            request, "admin/registration/userregistration/confirm_action.html", context
        )


admin.site.register(EmailBlock)
admin.site.register(IPBlock)
admin.site.register(UsernameRule)


# Monkey patching to ensure the registration app is always displayed first in the admin panel
admin.AdminSite._get_app_list = admin.AdminSite.get_app_list


def get_app_list(self, request, app_label=None):
    app_list = admin.AdminSite._get_app_list(self, request, app_label)
    if app_list:
        app_list.sort(key=lambda x: x["app_label"] != "registration")  # False < True
        app_list[0]["models"].sort(key=lambda x: x["object_name"] != "UserRegistration")
    return app_list


admin.AdminSite.get_app_list = get_app_list
