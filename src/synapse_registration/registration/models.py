from django.db import models


class UserRegistration(models.Model):
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
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username


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
