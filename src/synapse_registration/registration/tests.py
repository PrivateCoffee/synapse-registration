from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from .forms import EmailForm, UsernameForm
from .models import UsernameRule, UserRegistration
from .views import SynapseClient, SynapseError


class UsernameFormTests(TestCase):
    def test_clean_normalizes_username_to_lowercase(self):
        form = UsernameForm(data={"username": "Alice"})

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["username"], "alice")

    def test_permanent_username_rule_is_enforced(self):
        UsernameRule.objects.create(regex="^admin$", expires=None)

        form = UsernameForm(data={"username": "admin"})

        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)

    def test_active_username_rule_is_enforced(self):
        UsernameRule.objects.create(
            regex="^admin$", expires=timezone.now() + timedelta(days=1)
        )

        form = UsernameForm(data={"username": "admin"})

        self.assertFalse(form.is_valid())
        self.assertIn("username", form.errors)

    def test_expired_username_rule_is_not_enforced(self):
        UsernameRule.objects.create(
            regex="^admin$", expires=timezone.now() - timedelta(seconds=1)
        )

        form = UsernameForm(data={"username": "admin"})

        self.assertTrue(form.is_valid(), form.errors)


class EmailFormTests(TestCase):
    def _make_registration(self, email):
        return UserRegistration.objects.create(
            username="alice",
            email=email,
            registration_reason="test",
            ip_address="127.0.0.1",
            token=email,
        )

    def test_subaddress_is_stripped(self):
        form = EmailForm(data={"email": "alice+tag@example.com"})
        form.is_valid()
        self.assertEqual(form.cleaned_data["email"], "alice@example.com")

    def test_subaddress_variant_blocked_when_base_address_registered(self):
        self._make_registration("alice@example.com")
        form = EmailForm(data={"email": "alice+tag@example.com"})
        self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_base_address_blocked_when_subaddress_variant_registered(self):
        self._make_registration("alice+tag@example.com")
        form = EmailForm(data={"email": "alice@example.com"})
        self.assertFalse(form.is_valid())
        self.assertIn("email", form.errors)

    def test_denied_registration_does_not_block_retry(self):
        r = self._make_registration("alice@example.com")
        r.status = UserRegistration.STATUS_DENIED
        r.save()
        form = EmailForm(data={"email": "alice@example.com"})
        self.assertTrue(form.is_valid(), form.errors)


class SynapseClientTests(SimpleTestCase):
    def test_username_available_returns_false_for_user_in_use(self):
        response = Mock(status_code=400, text='{"errcode":"M_USER_IN_USE"}')
        response.json.return_value = {"errcode": "M_USER_IN_USE"}

        client = SynapseClient("https://synapse.test", "token", "example.com")
        client.session = Mock()
        client.session.get.return_value = response

        self.assertFalse(client.username_available("taken-user"))

    def test_username_available_raises_for_other_errors(self):
        response = Mock(status_code=500, text="server error")
        response.json.return_value = {"error": "boom"}

        client = SynapseClient("https://synapse.test", "token", "example.com")
        client.session = Mock()
        client.session.get.return_value = response

        with self.assertRaises(SynapseError):
            client.username_available("alice")


class CheckUsernameViewTests(TestCase):
    @patch("synapse_registration.registration.views.synapse_client")
    def test_taken_username_shows_field_error(self, mock_synapse_client):
        mock_synapse_client.return_value.username_available.return_value = False

        response = self.client.post(
            reverse("check_username"), {"username": "taken-user"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Username is not available.")

    @patch("synapse_registration.registration.views.synapse_client")
    def test_username_check_failure_shows_non_field_error(self, mock_synapse_client):
        mock_synapse_client.return_value.username_available.side_effect = SynapseError(
            "down"
        )

        response = self.client.post(reverse("check_username"), {"username": "alice"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Unable to check username availability right now. Please try again later.",
        )


class CompleteRegistrationViewTests(TestCase):
    @patch("django.core.mail.EmailMultiAlternatives.send", return_value=1)
    @patch("synapse_registration.registration.views.synapse_client")
    def test_successful_submission_redirects_to_completion_page(
        self, mock_synapse_client, _mock_send
    ):
        mock_synapse_client.return_value.username_available.return_value = True
        registration = UserRegistration.objects.create(
            username="alice",
            email="alice@example.com",
            registration_reason="",
            ip_address="127.0.0.1",
            token="token-123",
            email_verified=True,
            status=UserRegistration.STATUS_STARTED,
        )
        session = self.client.session
        session["registration"] = registration.id
        session.save()

        response = self.client.post(
            reverse("complete_registration"),
            {"registration_reason": "a" * 40},
        )

        self.assertRedirects(response, reverse("registration_complete"))
