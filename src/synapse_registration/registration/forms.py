from django import forms
from django.conf import settings
from django.utils import timezone

import re

from .models import EmailBlock, UsernameRule, UserRegistration


class UsernameForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(
            attrs={"class": "input", "placeholder": "Enter your desired username"}
        ),
    )

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get("username")

        if username.startswith("@") and username.endswith(f":{settings.MATRIX_DOMAIN}"):
            username = username[1 : -len(f":{settings.MATRIX_DOMAIN}")]

        if not username:
            self.add_error("username", "Username cannot be empty.")

        if not all(
            c in "abcdefghijklmnopqrstuvwxyz0123456789._=-" for c in username.lower()
        ):
            self.add_error(
                "username",
                "Sorry, your username can only contain the characters a-z, 0-9, ., _, =, -, and /.",
            )

        for rule in UsernameRule.objects.filter(expires__gt=timezone.now()):
            regex = re.compile(rule.regex)

            if regex.match(username):
                self.add_error(
                    "username", "Sorry, the provided username cannot be used."
                )
                break

        cleaned_data["username"] = username
        return cleaned_data


class EmailForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={"class": "input", "placeholder": "Enter your email address"}
        )
    )

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get("email")

        if UserRegistration.objects.filter(email=email).exists():
            self.add_error(
                "email", "You have recently registered with this email address."
            )

        for rule in EmailBlock.objects.filter(expires__gt=timezone.now()):
            regex = re.compile(rule.regex)

            if regex.match(email):
                self.add_error(
                    "email", "Sorry, the provided email address/domain is blocked."
                )
                break

        return cleaned_data


class RegistrationForm(forms.Form):
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(
            attrs={"class": "input", "placeholder": "Enter password"}
        ),
    )
    password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(
            attrs={"class": "input", "placeholder": "Re-enter password"}
        ),
    )
    registration_reason = forms.CharField(
        min_length=30,
        widget=forms.Textarea(
            attrs={
                "class": "textarea",
                "placeholder": "Please tell us a little bit about yourself. Why do you want to join our server? If you were referred by a current member, who referred you? If you found us through a different means, how did you find us?",
            }
        ),
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            self.add_error("password2", "Passwords do not match.")
