from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.conf import settings
from .models import UserRegistration


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
            # TODO: Unlock the user in Synapse

        elif status == UserRegistration.STATUS_DENIED:
            send_mail(
                "Registration Denied",
                f"Sorry, {instance.username}. Your registration request has been denied.",
                settings.DEFAULT_FROM_EMAIL,
                [instance.email],
            )
            # TODO: Deactivate the user in Synapse
