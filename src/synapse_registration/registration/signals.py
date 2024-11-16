from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings

from .models import UserRegistration

import requests


@receiver(post_save, sender=UserRegistration)
def handle_status_change(sender, instance, created, **kwargs):
    if not created:
        status = instance.status

        if status == UserRegistration.STATUS_APPROVED:
            response = requests.put(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{instance.username}:{settings.MATRIX_DOMAIN}",
                json={"locked": False},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            if response.status_code != 200:
                send_mail(
                    "Unlocking Failed",
                    f"Failed to unlock the user {instance.username}. Please unlock the user manually if required.",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                )

            send_mail(
                "Registration Approved",
                f"Congratulations, {instance.username}! Your registration at {settings.MATRIX_DOMAIN} has been approved.",
                settings.DEFAULT_FROM_EMAIL,
                [instance.email],
            )

        elif status == UserRegistration.STATUS_DENIED:
            send_mail(
                "Registration Denied",
                f"Sorry, your registration request at {settings.MATRIX_DOMAIN} has been denied.",
                settings.DEFAULT_FROM_EMAIL,
                [instance.email],
            )

            response = requests.put(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{instance.username}:{settings.MATRIX_DOMAIN}",
                json={"deactivated": True},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            for room in settings.AUTO_JOIN:
                response = requests.post(
                    f"{settings.SYNAPSE_SERVER}/_synapse/admin/v1/join/{room}",
                    json={"user_id": f"@{instance.username}:{settings.MATRIX_DOMAIN}"},
                    headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
                )

            if response.status_code != 200:
                send_mail(
                    "Deactivation Failed",
                    f"Failed to deactivate the user {instance.username}. Please deactivate the user manually if required.",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                )
