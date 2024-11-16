from django.views.generic import FormView, View, TemplateView
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.core.mail import send_mail
from django.conf import settings
from .forms import UsernameForm, EmailForm, RegistrationForm
from .models import UserRegistration
import requests
from secrets import token_urlsafe


class LandingPageView(TemplateView):
    template_name = "landing_page.html"


class ErrorPageView(TemplateView):
    template_name = "error_page.html"


class CheckUsernameView(FormView):
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


class EmailInputView(FormView):
    template_name = "registration/email_form.html"
    form_class = EmailForm

    def form_valid(self, form):
        email = form.cleaned_data["email"]

        if UserRegistration.objects.filter(email=email).exists():
            form.add_error(
                "email",
                "This email is already registered. Please use a different email address.",
            )
            return self.form_invalid(form)

        token = token_urlsafe(32)

        if not settings.TRUST_PROXY:
            ip_address = self.request.META.get("REMOTE_ADDR")
        else:
            ip_address = self.request.META.get("HTTP_X_FORWARDED_FOR")

        UserRegistration.objects.create(
            username=self.request.session["username"],
            email=email,
            token=token,
            ip_address=ip_address,
        )
        verification_link = self.request.build_absolute_uri(
            reverse_lazy("verify_email", args=[token])
        )
        send_mail(
            "Verify your email",
            f"Click the link to verify your email: {verification_link}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )
        return render(self.request, "registration/email_sent.html")


class VerifyEmailView(View):
    def get(self, request, token):
        registration = get_object_or_404(UserRegistration, token=token)
        request.session["registration"] = registration.id
        if registration.email_verified:
            return render(request, "registration/already_verified.html")
        registration.email_verified = True
        registration.save()
        return redirect("complete_registration")


class CompleteRegistrationView(FormView):
    template_name = "registration/complete_registration.html"
    form_class = RegistrationForm
    success_url = reverse_lazy("registration_complete")

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
            return render(self.request, "registration/registration_forbidden.html")

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

        if response.status_code in (200, 201):
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
                    "Locking Failed",
                    f"Failed to lock the user {username}. Please lock the user manually if required.",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                )

            registration.status = UserRegistration.STATUS_REQUESTED
            registration.registration_reason = registration_reason
            registration.save()
            send_mail(
                "New Registration Request",
                f"Approve the new user {username}",
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
            self.registration.status != UserRegistration.STATUS_REQUESTED
            or not self.registration.email_verified
        ):
            return render(request, "registration/registration_forbidden.html")
        return super().dispatch(request, *args, **kwargs)
