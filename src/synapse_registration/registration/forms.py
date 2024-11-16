from django import forms
from django.conf import settings


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
                "Username can only contain the characters a-z, 0-9, ., _, =, -, and /.",
            )

        cleaned_data["username"] = username
        return cleaned_data


class EmailForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={"class": "input", "placeholder": "Enter your email address"}
        )
    )


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
                "placeholder": "Why do you want to join our server? If you were referred by a current member, who referred you? If you found us through a different means, how did you find us?",
            }
        ),
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            self.add_error("password2", "Passwords do not match.")
