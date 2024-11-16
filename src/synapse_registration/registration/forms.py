from django import forms


class UsernameForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(
            attrs={"class": "input", "placeholder": "Enter your desired username"}
        ),
    )


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
        )
    )
    password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(
            attrs={"class": "input", "placeholder": "Re-enter password"}
        )
    )
    registration_reason = forms.CharField(
        min_length=30,
        widget=forms.Textarea(
            attrs={
                "class": "textarea",
                "placeholder": "Why do you want to join our server? If you were referred by a current member, who referred you? If you found us through a different means, how did you find us?",
            }
        )
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            self.add_error("password2", "Passwords do not match.")
