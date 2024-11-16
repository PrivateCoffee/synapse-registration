from django.apps import AppConfig


class RegistrationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "synapse_registration.registration"

    def ready(self):
        import synapse_registration.registration.signals  # noqa: F401
