from django.db import models

class UserRegistration(models.Model):
    # Status constants
    STATUS_REQUESTED = 1
    STATUS_APPROVED = 2
    STATUS_DENIED = 3

    # Status choices
    STATUS_CHOICES = [
        (STATUS_REQUESTED, 'Requested'),
        (STATUS_APPROVED, 'Approved'),
        (STATUS_DENIED, 'Denied'),
    ]

    username = models.CharField(max_length=150)
    email = models.EmailField()
    registration_reason = models.TextField()
    ip_address = models.GenericIPAddressField()
    status = models.IntegerField(choices=STATUS_CHOICES, default=STATUS_REQUESTED)
    token = models.CharField(max_length=64, unique=True)
    email_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username
