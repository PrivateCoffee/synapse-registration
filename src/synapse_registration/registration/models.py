from django.db import models
from django.conf import settings


class UserRegistration(models.Model):
    """
    Represents a user registration attempt, including all relevant information and status.
    """
    # Status constants
    STATUS_STARTED = 0
    STATUS_REQUESTED = 1
    STATUS_APPROVED = 2
    STATUS_DENIED = 3
    STATUS_COMPLETED = 4

    # Status choices
    STATUS_CHOICES = [
        (STATUS_STARTED, "Started"),
        (STATUS_REQUESTED, "Requested"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_DENIED, "Denied"),
        (STATUS_COMPLETED, "Completed"),
    ]

    username = models.CharField(max_length=150)
    email = models.EmailField()
    registration_reason = models.TextField()
    ip_address = models.GenericIPAddressField()
    status = models.IntegerField(choices=STATUS_CHOICES, default=STATUS_STARTED)
    token = models.CharField(max_length=64, unique=True)
    email_verified = models.BooleanField(default=False)
    mod_message = models.TextField(blank=True, default="")
    notify = models.BooleanField(default=True)

    def __str__(self):
        return self.username


class RegistrationEvent(models.Model):
    """
    Append-only audit trail for a registration.
    """
    class Type(models.TextChoices):
        STARTED = "started", "Started"
        USERNAME_CHECK_OK = "username_check_ok", "Username availability confirmed"
        USERNAME_CHECK_FAIL = "username_check_fail", "Username unavailable / check failed"

        EMAIL_SUBMITTED = "email_submitted", "Email submitted"
        EMAIL_VERIFICATION_SENT = "email_verification_sent", "Verification email sent"
        EMAIL_VERIFICATION_SEND_FAILED = "email_verification_send_failed", "Verification email failed to send"
        EMAIL_VERIFIED = "email_verified", "Email verified"

        REGISTRATION_REASON_SUBMITTED = "reason_submitted", "Registration reason submitted"
        REQUESTED = "requested", "Registration requested (awaiting admin)"

        MATRIX_ADMIN_NOTIFIED = "admin_notified", "Matrix: admin room notified of registration request"
        MATRIX_ADMIN_NOTIFICATION_FAILED = "admin_notification_failed", "Matrix: Failed to notify admin room"

        APPROVED = "approved", "Approved by admin"
        DENIED = "denied", "Denied by admin"

        PASSWORD_SET_FORM_OPENED = "password_form_opened", "Password set link opened"
        USER_CREATED = "user_created", "Synapse user created"
        USER_CREATE_FAILED = "user_create_failed", "Synapse user creation failed"

        AUTOJOIN_OK = "autojoin_ok", "Auto-join room succeeded"
        AUTOJOIN_FAIL = "autojoin_fail", "Auto-join room failed"

        CONSENT_OK = "consent_ok", "Consent submitted & verified"
        CONSENT_FAIL = "consent_fail", "Consent submission/verification failed"

        WELCOME_SENT = "welcome_sent", "Matrix welcome message sent"
        WELCOME_SEND_FAILED = "welcome_send_failed", "Matrix welcome message failed to send"

        COMPLETED = "completed", "Registration completed"

    registration = models.ForeignKey(
        UserRegistration, related_name="events", on_delete=models.CASCADE
    )
    type = models.CharField(max_length=64, choices=Type.choices)
    occurred_at = models.DateTimeField(auto_now_add=True)

    # Who triggered the event (i.e. admin user for approve/deny)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )

    ip_address = models.GenericIPAddressField(null=True, blank=True)

    # For anything else we might want to save (responses from Synapse, etc.)
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["registration", "occurred_at"]),
            models.Index(fields=["type", "occurred_at"]),
        ]
        ordering = ["occurred_at", "id"]

    def __str__(self):
        return f"{self.registration_id} {self.type} @ {self.occurred_at}"


class IPBlock(models.Model):
    network = models.GenericIPAddressField()
    netmask = models.SmallIntegerField(default=-1)
    reason = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.netmask == -1:
            self.netmask = 32 if self.network.version == 4 else 128
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.network}/{self.netmask}"


class EmailBlock(models.Model):
    regex = models.CharField(max_length=1024)
    reason = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.regex


class UsernameRule(models.Model):
    regex = models.CharField(max_length=1024)
    reason = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.regex
