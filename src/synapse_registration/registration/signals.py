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
            send_mail(
                "Registration Approved",
                f"Congratulations, {instance.username}! Your registration has been approved.",
                settings.DEFAULT_FROM_EMAIL,
                [instance.email],
            )

            requests.put(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{instance.username}:{settings.MATRIX_DOMAIN}",
                json={"locked": False},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            response = requests.post(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/{settings.ADMIN_USER}/rooms?access_token={settings.SYNAPSE_ADMIN_TOKEN}",
                json={"preset": "private_chat"},
            )

            room_id = response.json()["room_id"]

            response = requests.post(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/rooms/{room_id}/invite",
                json={"user_id": f"@{instance.username}:{settings.MATRIX_DOMAIN}"},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            response = requests.post(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/rooms/{room_id}/send",
                json={"msgtype": "m.text", "body": f"Welcome, {instance.username}!"},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

        elif status == UserRegistration.STATUS_DENIED:
            send_mail(
                "Registration Denied",
                f"Sorry, {instance.username}. Your registration request has been denied.",
                settings.DEFAULT_FROM_EMAIL,
                [instance.email],
            )

            response = requests.put(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{instance.username}:{settings.MATRIX_DOMAIN}",
                json={"deactivated": True},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            if response.status_code != 200:
                send_mail(
                    "Deactivation Failed",
                    f"Failed to deactivate the user {instance.username}. Please deactivate the user manually if required.",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                )
