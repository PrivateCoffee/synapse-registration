from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from django.db.models import OuterRef, Subquery, DateTimeField
from django.db.models.functions import Coalesce

from ...models import (
    UserRegistration,
    IPBlock,
    EmailBlock,
    UsernameRule,
    RegistrationEvent,
)
from django.conf import settings


class Command(BaseCommand):
    help = "Clean up old user registrations and blocks"

    def handle(self, *args, **options):
        now = timezone.now()

        retention_started_days = getattr(settings, "RETENTION_STARTED", 2)
        retention_completed_days = getattr(settings, "RETENTION_COMPLETED", 30)

        started_cutoff = now - timedelta(days=retention_started_days)
        completed_cutoff = now - timedelta(days=retention_completed_days)

        # Subquery: started_at (first STARTED event)
        started_sq = (
            RegistrationEvent.objects.filter(
                registration=OuterRef("pk"),
                type=RegistrationEvent.Type.STARTED,
            )
            .order_by("occurred_at")
            .values("occurred_at")[:1]
        )

        # Subquery: terminal_at (last COMPLETED or DENIED event)
        terminal_sq = (
            RegistrationEvent.objects.filter(
                registration=OuterRef("pk"),
                type__in=[
                    RegistrationEvent.Type.COMPLETED,
                    RegistrationEvent.Type.DENIED,
                ],
            )
            .order_by("-occurred_at")
            .values("occurred_at")[:1]
        )

        # Subquery: last_event_at
        last_event_sq = (
            RegistrationEvent.objects.filter(
                registration=OuterRef("pk"),
            )
            .order_by("-occurred_at")
            .values("occurred_at")[:1]
        )

        regs = UserRegistration.objects.annotate(
            started_at=Subquery(started_sq, output_field=DateTimeField()),
            terminal_at=Subquery(terminal_sq, output_field=DateTimeField()),
            last_event_at=Subquery(last_event_sq, output_field=DateTimeField()),
            effective_terminal_at=Coalesce(
                Subquery(terminal_sq, output_field=DateTimeField()),
                Subquery(last_event_sq, output_field=DateTimeField()),
            ),
        )

        # 1) Remove started that never progressed and are older than retention_started
        started_qs = regs.filter(
            status=UserRegistration.STATUS_STARTED,
            started_at__lt=started_cutoff,
        )
        started_deleted = started_qs.count()
        started_qs.delete()

        # 2) Remove completed/denied older than retention_completed
        terminal_qs = regs.filter(
            status__in=[
                UserRegistration.STATUS_COMPLETED,
                UserRegistration.STATUS_DENIED,
            ],
            effective_terminal_at__lt=completed_cutoff,
        )
        terminal_deleted = terminal_qs.count()
        terminal_qs.delete()

        self.stdout.write(
            self.style.SUCCESS(
                f"Cleaned registrations: started={started_deleted}, terminal={terminal_deleted}"
            )
        )

        # Blocks cleanup (unchanged)
        IPBlock.objects.filter(expires__lt=now).delete()
        EmailBlock.objects.filter(expires__lt=now).delete()
        UsernameRule.objects.filter(expires__lt=now).delete()
        self.stdout.write(self.style.SUCCESS("Successfully cleaned up old blocks"))
