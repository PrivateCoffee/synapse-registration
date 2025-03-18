from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings

from .models import UserRegistration

import requests

import hashlib
import hmac

from smtplib import SMTPRecipientsRefused
from textwrap import dedent


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

            if settings.POLICY_VERSION and settings.FORM_SECRET:
                userhmac = hmac.HMAC(
                    settings.FORM_SECRET.encode("utf-8"),
                    instance.username.encode("utf-8"),
                    digestmod=hashlib.sha256,
                ).hexdigest()

                form_data = {
                    "v": settings.POLICY_VERSION,
                    "u": instance.username,
                    "h": userhmac,
                }

                response = requests.post(
                    f"{settings.SYNAPSE_SERVER}/_matrix/consent",
                    data=form_data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

            if instance.notify:
                context = {
                    "matrix_domain": settings.MATRIX_DOMAIN,
                    "mod_message": instance.mod_message,
                    "logo": getattr(settings, "LOGO_URL", None),
                }

                subject = f"[{settings.MATRIX_DOMAIN}] Matrix Registration Approved"

                text_content = render_to_string(
                    "registration/email/txt/registration-approved.txt", context
                )

                msg = EmailMultiAlternatives(
                    subject, text_content, settings.DEFAULT_FROM_EMAIL, [instance.email]
                )

                try:
                    html_content = render_to_string(
                        "registration/email/mjml/registration-approved.mjml", context
                    )

                    msg.attach_alternative(html_content, "text/html")

                except Exception:
                    pass

                try:
                    msg.send()
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
                context = {
                    "matrix_domain": settings.MATRIX_DOMAIN,
                    "mod_message": instance.mod_message,
                    "logo": getattr(settings, "LOGO_URL", None),
                }

                subject = f"[{settings.MATRIX_DOMAIN}] Matrix Registration Denied"

                text_content = render_to_string(
                    "registration/email/txt/registration-denied.txt", context
                )

                msg = EmailMultiAlternatives(
                    subject, text_content, settings.DEFAULT_FROM_EMAIL, [instance.email]
                )

                try:
                    html_content = render_to_string(
                        "registration/email/mjml/registration-denied.mjml", context
                    )

                    msg.attach_alternative(html_content, "text/html")

                except Exception:
                    pass

                try:
                    msg.send()
                except SMTPRecipientsRefused:
                    pass
