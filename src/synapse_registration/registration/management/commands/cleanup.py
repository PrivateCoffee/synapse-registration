from django.core.management.base import BaseCommand
from django.utils import timezone

from ...models import UserRegistration, IPBlock, EmailBlock, UsernameRule

from datetime import timedelta


class Command(BaseCommand):
    help = "Clean up old user registrations and blocks"

    def handle(self, *args, **options):
        # Remove all registrations that are still in the "started" state after 48 hours
        UserRegistration.objects.filter(
            status=UserRegistration.STATUS_STARTED,
            timestamp__lt=timezone.now() - timedelta(hours=48),
        ).delete()

        # Remove all other registrations that are older than 30 days
        UserRegistration.objects.filter(
            timestamp__lt=timezone.now() - timedelta(days=30),
        ).delete()

        self.stdout.write(
            self.style.SUCCESS("Successfully cleaned up old user registrations")
        )

        # Remove all IP blocks that have expired
        IPBlock.objects.filter(expires__lt=timezone.now()).delete()

        # Remove all email blocks that have expired
        EmailBlock.objects.filter(expires__lt=timezone.now()).delete()

        # Remove all username rules that have expired
        UsernameRule.objects.filter(expires__lt=timezone.now()).delete()

        self.stdout.write(self.style.SUCCESS("Successfully cleaned up old blocks"))
