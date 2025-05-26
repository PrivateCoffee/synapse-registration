from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.urls import reverse

from .models import UserRegistration

from smtplib import SMTPRecipientsRefused


@receiver(post_save, sender=UserRegistration)
def handle_status_change(sender, instance, created, **kwargs):
    if not created and instance.status == UserRegistration.STATUS_APPROVED:
        # When an admin approves a registration, send the user a link to set their password
        if instance.notify:
            set_password_url = (
                f"{settings.SITE_URL}{reverse('set_password', args=[instance.token])}"
            )

            context = {
                "matrix_domain": settings.MATRIX_DOMAIN,
                "username": instance.username,
                "mod_message": instance.mod_message,
                "set_password_url": set_password_url,
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

    elif not created and instance.status == UserRegistration.STATUS_DENIED:
        # When an admin denies a registration, just inform the user via email
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
