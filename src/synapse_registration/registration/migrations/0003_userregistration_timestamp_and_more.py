# Generated by Django 5.1.3 on 2024-11-16 20:22

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registration", "0002_alter_userregistration_email_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="userregistration",
            name="timestamp",
            field=models.DateTimeField(
                auto_now_add=True, default=django.utils.timezone.now
            ),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="userregistration",
            name="status",
            field=models.IntegerField(
                choices=[
                    (0, "Started"),
                    (1, "Requested"),
                    (2, "Approved"),
                    (3, "Denied"),
                ],
                default=0,
            ),
        ),
    ]
