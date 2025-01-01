from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings

from .models import UserRegistration

import requests

from smtplib import SMTPRecipientsRefused


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
                    f"[{settings.MATRIX_DOMAIN}] Unlocking Failed",
                    f"Failed to unlock the user {instance.username}. Please unlock the user manually if required.",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                )

            for room in settings.AUTO_JOIN:
                response = requests.post(
                    f"{settings.SYNAPSE_SERVER}/_synapse/admin/v1/join/{room}",
                    json={"user_id": f"@{instance.username}:{settings.MATRIX_DOMAIN}"},
                    headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
                )

            if instance.notify:
                message = f"""Hi {instance.username},
                
                Congratulations, your registration request at {settings.MATRIX_DOMAIN} has been approved.
                
                You can now login to your account and start chatting with other users. Have fun! 🎉"""

                if instance.mod_message:
                    message += f"\n\nMessage from moderator: {instance.mod_message}"

                message += f"\n\n{settings.MATRIX_DOMAIN} Team"

                try:
                    send_mail(
                        f"[{settings.MATRIX_DOMAIN}] Matrix Registration Approved",
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [instance.email],
                    )
                except SMTPRecipientsRefused:
                    pass

        elif status == UserRegistration.STATUS_DENIED:
            response = requests.put(
                f"{settings.SYNAPSE_SERVER}/_synapse/admin/v2/users/@{instance.username}:{settings.MATRIX_DOMAIN}",
                json={"deactivated": True},
                headers={"Authorization": f"Bearer {settings.SYNAPSE_ADMIN_TOKEN}"},
            )

            if response.status_code != 200:
                send_mail(
                    f"[{settings.MATRIX_DOMAIN}] Deactivation Failed",
                    f"Failed to deactivate the user {instance.username}. Please deactivate the user manually if required.",
                    settings.DEFAULT_FROM_EMAIL,
                    [settings.ADMIN_EMAIL],
                )

            if instance.notify:
                message = f"""Hi,
                
                Sorry, your registration request at {settings.MATRIX_DOMAIN} has been denied."""

                if instance.mod_message:
                    message += f"\n\nMessage from moderator: {instance.mod_message}"

                message += f"\n\n{settings.MATRIX_DOMAIN} Team"

                try:
                    send_mail(
                        f"[{settings.MATRIX_DOMAIN}] Matrix Registration Denied",
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [instance.email],
                    )
                except SMTPRecipientsRefused:
                    pass
