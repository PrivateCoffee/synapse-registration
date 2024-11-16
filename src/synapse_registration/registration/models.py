from django.db import models


class UserRegistration(models.Model):
    # Status constants
    STATUS_STARTED = 0
    STATUS_REQUESTED = 1
    STATUS_APPROVED = 2
    STATUS_DENIED = 3

    # Status choices
    STATUS_CHOICES = [
        (STATUS_STARTED, "Started"),
        (STATUS_REQUESTED, "Requested"),
        (STATUS_APPROVED, "Approved"),
        (STATUS_DENIED, "Denied"),
    ]

    username = models.CharField(max_length=150)
    email = models.EmailField()
    registration_reason = models.TextField()
    ip_address = models.GenericIPAddressField()
    status = models.IntegerField(choices=STATUS_CHOICES, default=STATUS_STARTED)
    token = models.CharField(max_length=64, unique=True)
    email_verified = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username
