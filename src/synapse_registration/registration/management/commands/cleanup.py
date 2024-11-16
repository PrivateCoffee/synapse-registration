from django.core.management.base import BaseCommand

from ...models import UserRegistration

from datetime import timedelta, datetime


class Command(BaseCommand):
    help = "Clean up old user registrations"

    def handle(self, *args, **options):
        # Remove all registrations that are still in the "started" state after 48 hours
        UserRegistration.objects.filter(
            status=UserRegistration.STATUS_STARTED,
            timestamp__lt=datetime.now() - timedelta(hours=48),
        ).delete()

        # Remove all registrations that are denied or approved after 30 days
        UserRegistration.objects.filter(
            status__in=[UserRegistration.STATUS_DENIED, UserRegistration.STATUS_APPROVED],
            timestamp__lt=datetime.now() - timedelta(days=30),
        ).delete()

        self.stdout.write(
            self.style.SUCCESS("Successfully cleaned up old user registrations")
        )
