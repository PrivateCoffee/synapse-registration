# Generated by Django 5.1.3 on 2024-11-16 13:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("registration", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="userregistration",
            name="email",
            field=models.EmailField(max_length=254),
        ),
        migrations.AlterField(
            model_name="userregistration",
            name="username",
            field=models.CharField(max_length=150),
        ),
    ]
