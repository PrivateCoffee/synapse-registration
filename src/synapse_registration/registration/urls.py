from django.urls import path
from . import views

urlpatterns = [
    path("", views.LandingPageView.as_view(), name="landing_page"),
    path("error/", views.ErrorPageView.as_view(), name="error_page"),
    path("check-username/", views.CheckUsernameView.as_view(), name="check_username"),
    path("email-input/", views.EmailInputView.as_view(), name="email_input"),
    path(
        "verify-email/<str:token>/",
        views.VerifyEmailView.as_view(),
        name="verify_email",
    ),
    path(
        "complete-registration/",
        views.CompleteRegistrationView.as_view(),
        name="complete_registration",
    ),
    path(
        "registration-complete/",
        views.TemplateView.as_view(
            template_name="registration/registration_complete.html"
        ),
        name="registration_complete",
    ),
    path(
        "set-password/<str:token>/",
        views.SetPasswordView.as_view(),
        name="set_password",
    ),
    path(
        "password-set-success/",
        views.PasswordSetSuccessView.as_view(),
        name="password_set_success",
    ),
]
