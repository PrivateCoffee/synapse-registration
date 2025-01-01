from django.views.generic import FormView, View, TemplateView
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

from .forms import UsernameForm, EmailForm, RegistrationForm
from .models import UserRegistration, IPBlock

import requests

from secrets import token_urlsafe
from datetime import timedelta
from smtplib import SMTPRecipientsRefused
from ipaddress import ip_network


class RateLimitMixin:
    def dispatch(self, request, *args, **kwargs):
        if not settings.TRUST_PROXY:
            ip_address = request.META.get("REMOTE_ADDR")
        else:
            ip_address = request.META.get("HTTP_X_FORWARDED_FOR")

        for block in IPBlock.objects.filter(expires__gt=timezone.now()):
            if ip_network(ip_address) in ip_network(f"{block.network}/{block.netmask}"):
                return render(request, "registration/ratelimit.html", status=429)

        return super().dispatch(request, *args, **kwargs)


class LandingPageView(TemplateView):
    template_name = "landing_page.html"


class ErrorPageView(TemplateView):
    template_name = "error_page.html"


class CheckUsernameView(RateLimitMixin, FormView):
    template_name = "registration/username_form.html"
    form_class = UsernameForm
    success_url = reverse_lazy("email_input")

    def form_valid(self, form):
        username = form.cleaned_data["username"]
        response = requests.get(
            f"{settings.SYNAPSE_SERVER}/_synapse/admin/v1/username_available?username={username}",
            headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
        )

        if response.json().get("available"):
            self.request.session["username"] = username
            return super().form_valid(form)
        else:
            form.add_error("username", "Username is not available.")
            return self.form_invalid(form)


class EmailInputView(RateLimitMixin, FormView):
    template_name = "registration/email_form.html"
    form_class = EmailForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["legal_links"] = settings.LEGAL_LINKS
        return context

    def form_valid(self, form):
        email = form.cleaned_data["email"]

        if UserRegistration.objects.filter(email=email).exists():
            form.add_error(
                "email",
                "There is already a pending or recently accepted registration for this email address. Please get in touch if you need multiple accounts.",
            )
            return self.form_invalid(form)

        if not settings.TRUST_PROXY:
            ip_address = self.request.META.get("REMOTE_ADDR")
        else:
            ip_address = self.request.META.get("HTTP_X_FORWARDED_FOR")

        if (
            UserRegistration.objects.filter(
                ip_address=ip_address,
                timestamp__gte=timezone.now() - timedelta(hours=24),
            ).count()
            >= 5
        ):
            return render(self.request, "registration/ratelimit.html", status=429)

        token = token_urlsafe(32)

        registration = UserRegistration.objects.create(
            username=self.request.session["username"],
            email=email,
            token=token,
            ip_address=ip_address,
        )

        verification_link = self.request.build_absolute_uri(
            reverse_lazy("verify_email", args=[token])
        )

        try:
            send_mail(
                f"[{settings.MATRIX_DOMAIN}] Verify your email",
                f"""Hi,
                
                Someone (hopefully you) requested a new account at {settings.MATRIX_DOMAIN}. If this was you, please click the link below to verify your email address.

                {verification_link}
                
                Thanks!

                {settings.MATRIX_DOMAIN} Team
                """,
                settings.DEFAULT_FROM_EMAIL,
                [email],
            )
            return render(self.request, "registration/email_sent.html")

        except SMTPRecipientsRefused:
            form.add_error(
                "email",
                "Your email address is invalid, not accepting mail, or blocked by our mail server.",
            )
            registration.delete()
            return self.form_invalid(form)


class VerifyEmailView(RateLimitMixin, View):
    def get(self, request, token):
        try:
            registration = UserRegistration.objects.get(token=token)
        except UserRegistration.DoesNotExist:
            return render(
                request, "registration/registration_forbidden.html", status=403
            )

        if registration.status != UserRegistration.STATUS_STARTED:
            return render(
                request, "registration/registration_forbidden.html", status=403
            )

        request.session["registration"] = registration.id
        registration.email_verified = True
        registration.save()
        return redirect("complete_registration")


class CompleteRegistrationView(RateLimitMixin, FormView):
    template_name = "registration/complete_registration.html"
    form_class = RegistrationForm
    success_url = reverse_lazy("registration_complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["legal_links"] = settings.LEGAL_LINKS
        return context

    def form_valid(self, form):
        password = form.cleaned_data["password1"]
        registration_reason = form.cleaned_data["registration_reason"]
        registration = get_object_or_404(
            UserRegistration, id=self.request.session.get("registration")
        )
        username = registration.username

        # Assert one last time that the username is available
        response = requests.get(
            f"{settings.SYNAPSE_SERVER}/_synapse/admin/v1/username_available?username={username}",
            headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
        )

        if not response.json().get("available"):
            return render(
                self.request, "registration/registration_forbidden.html", status=403
            )

        response = requests.put(
            f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{username}:{settings.MATRIX_DOMAIN}",
            json={
                "password": password,
                "displayname": username,
                "threepids": [{"medium": "email", "address": registration.email}],
                "locked": True,
            },
            headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
        )

        if response.status_code == 200:
            # Oops. This should never happen. It means that an existing user was altered.
            send_mail(
                f"[{settings.MATRIX_DOMAIN}] Critical Registration Error",
                f"Something went horribly wrong. The existing user {username} was altered. Please investigate.",
                settings.DEFAULT_FROM_EMAIL,
                [settings.ADMIN_EMAIL],
            )

            return render(
                self.request, "registration/registration_forbidden.html", status=403
            )

        if response.status_code == 201:
            # The "locked" field doesn't seem to work when creating a user, so we need to lock the user after creation
            response = requests.put(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{username}:{settings.MATRIX_DOMAIN}",
                json={"locked": True},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            response = requests.get(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{username}:{settings.MATRIX_DOMAIN}",
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            if not response.json().get("locked"):
                send_mail(
                    f"[{settings.MATRIX_DOMAIN}] Locking Failed",
                    f"Failed to lock the user {username}. Please lock the user manually if required.",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                )

            registration.status = UserRegistration.STATUS_REQUESTED
            registration.registration_reason = registration_reason
            registration.save()

            try:
                self.request.session.pop("registration")
                self.request.session.pop("username")
            except KeyError:
                pass

            send_mail(
                f"[{settings.MATRIX_DOMAIN}] New Registration Request",
                f"Approve the new user {username}\n\nSupplied reason: {registration_reason}",
                settings.DEFAULT_FROM_EMAIL,
                [settings.ADMIN_EMAIL],
            )

            return render(self.request, "registration/registration_pending.html")

        form.add_error(None, "Registration failed.")
        return self.form_invalid(form)

    def dispatch(self, request, *args, **kwargs):
        self.registration = get_object_or_404(
            UserRegistration, id=self.request.session.get("registration")
        )
        if (
            self.registration.status != UserRegistration.STATUS_STARTED
            or not self.registration.email_verified
        ):
            return render(
                request, "registration/registration_forbidden.html", status=403
            )
        return super().dispatch(request, *args, **kwargs)
