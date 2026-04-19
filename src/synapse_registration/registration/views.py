import hashlib
import hmac
import logging
import re
import time
import uuid

from datetime import datetime, timedelta
from ipaddress import ip_network
from secrets import token_urlsafe

import requests

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.generic import FormView, TemplateView, View
from smtplib import SMTPRecipientsRefused

from .forms import EmailForm, PasswordForm, RegistrationReasonForm, UsernameForm
from .management.commands.cleanup import Command as CleanupCommand
from .models import EmailBlock, IPBlock, UserRegistration, RegistrationEvent
from .audit import log_event

logger = logging.getLogger(__name__)


class SynapseError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class SynapseClient:
    def __init__(
        self,
        server: str,
        admin_token: str,
        matrix_domain: str,
        verify_cert: bool = True,
    ):
        self.server = server
        self.admin_token = admin_token
        self.matrix_domain = matrix_domain
        self.verify_cert = verify_cert
        self.session = requests.Session()

    def _headers(self):
        return {"Authorization": f"Bearer {self.admin_token}"}

    def username_available(self, username: str) -> bool:
        r = self.session.get(
            f"{self.server}/_synapse/admin/v1/username_available",
            params={"username": username},
            headers=self._headers(),
            verify=self.verify_cert,
            timeout=15,
        )
        if r.status_code == 400:
            try:
                if r.json().get("errcode") == "M_USER_IN_USE":
                    return False
            except ValueError:
                pass
        if r.status_code != 200:
            raise SynapseError(
                f"username_available failed: {r.status_code} {r.text}",
                status_code=r.status_code,
            )
        return bool(r.json().get("available"))

    def create_user(self, username: str, password: str, email: str) -> None:
        r = self.session.put(
            f"{self.server}/_synapse/admin/v2/users/@{username}:{self.matrix_domain}",
            json={
                "password": password,
                "displayname": username,
                "threepids": [{"medium": "email", "address": email}],
            },
            headers=self._headers(),
            verify=self.verify_cert,
            timeout=30,
        )
        if r.status_code != 201:
            raise SynapseError(
                f"create_user failed: {r.status_code} {r.text}",
                status_code=r.status_code,
            )

    def join_room(self, room_id: str, user_id: str) -> None:
        r = self.session.post(
            f"{self.server}/_synapse/admin/v1/join/{room_id}",
            json={"user_id": user_id},
            headers=self._headers(),
            verify=self.verify_cert,
            timeout=30,
        )
        if r.status_code not in (200, 201):
            raise SynapseError(
                f"join_room failed: {r.status_code} {r.text}", status_code=r.status_code
            )

    def get_user(self, user_id: str) -> dict:
        r = self.session.get(
            f"{self.server}/_synapse/admin/v2/users/{user_id}",
            headers=self._headers(),
            verify=self.verify_cert,
            timeout=15,
        )
        if r.status_code != 200:
            raise SynapseError(
                f"get_user failed: {r.status_code} {r.text}", status_code=r.status_code
            )
        return r.json()

    def get_user_consent_ts(self, user_id: str) -> int | None:
        return self.get_user(user_id).get("consent_ts")

    def send_room_message(
        self, room_id: str, body: str, msgtype: str = "m.text"
    ) -> None:
        txn_id = str(uuid.uuid4())
        r = self.session.put(
            f"{self.server}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn_id}",
            json={"msgtype": msgtype, "body": body},
            headers=self._headers(),
            verify=self.verify_cert,
            timeout=15,
        )
        if r.status_code not in (200, 201):
            raise SynapseError(
                f"send_room_message failed: {r.status_code} {r.text}",
                status_code=r.status_code,
            )

    def create_dm_room(self, user_id: str) -> str:
        r = self.session.post(
            f"{self.server}/_matrix/client/v3/createRoom",
            json={
                "is_direct": True,
                "invite": [user_id],
                "preset": "trusted_private_chat",
            },
            headers=self._headers(),
            verify=self.verify_cert,
            timeout=20,
        )
        if r.status_code not in (200, 201):
            raise SynapseError(
                f"create_dm_room failed: {r.status_code} {r.text}",
                status_code=r.status_code,
            )
        return r.json()["room_id"]

    def join_room_client(self, room_id_or_alias: str) -> None:
        # This will also accept an invite if there is one
        r = self.session.post(
            f"{self.server}/_matrix/client/v3/join/{room_id_or_alias}",
            json={},
            headers=self._headers(),
            verify=self.verify_cert,
            timeout=20,
        )
        if r.status_code not in (200, 201):
            raise SynapseError(
                f"join_room_client failed: {r.status_code} {r.text}",
                status_code=r.status_code,
            )

    def send_room_message_with_join_fallback(
        self, room_id: str, body: str, msgtype: str = "m.text"
    ) -> None:
        try:
            self.send_room_message(room_id, body, msgtype=msgtype)
            return
        except SynapseError as e:
            if e.status_code not in (403, 404):
                raise

        # Try to accept invite/join, then retry once
        self.join_room_client(room_id)
        self.send_room_message(room_id, body, msgtype=msgtype)


class ConsentError(RuntimeError):
    pass


def _user_hmac(form_secret: str, username: str) -> str:
    return hmac.new(
        form_secret.encode("utf-8"),
        username.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def submit_consent(
    *,
    synapse_server: str,
    policy_version: str,
    form_secret: str,
    username: str,
    verify_cert: bool,
    session: requests.Session,
) -> None:
    payload = {
        "v": policy_version,
        "u": username,
        "h": _user_hmac(form_secret, username),
    }
    r = session.post(
        f"{synapse_server}/_matrix/consent",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        allow_redirects=True,
        verify=verify_cert,
        timeout=20,
    )

    if r.status_code >= 500:
        raise ConsentError(f"Consent submission server error: {r.status_code}")
    if r.status_code != 200:
        raise ConsentError(f"Consent submission failed: {r.status_code} {r.text}")


def submit_and_verify_consent_via_consent_ts(
    *,
    synapse: SynapseClient,
    synapse_server: str,
    policy_version: str,
    form_secret: str,
    username: str,
    user_id: str,
    verify_cert: bool,
    retries: int = 6,
    retry_delay: float = 0.4,
) -> int:
    before = synapse.get_user_consent_ts(user_id)
    submit_consent(
        synapse_server=synapse_server,
        policy_version=policy_version,
        form_secret=form_secret,
        username=username,
        verify_cert=verify_cert,
        session=synapse.session,
    )

    last = None
    for _ in range(retries):
        last = synapse.get_user_consent_ts(user_id)
        if last is not None and (before is None or last >= before):
            return last
        time.sleep(retry_delay)

    raise ConsentError(
        f"Consent not reflected in consent_ts (before={before}, after={last})"
    )


def synapse_client() -> SynapseClient:
    return SynapseClient(
        server=settings.SYNAPSE_SERVER,
        admin_token=settings.SYNAPSE_ADMIN_TOKEN,
        matrix_domain=settings.MATRIX_DOMAIN,
        verify_cert=settings.VERIFY_CERT,
    )


class ContextMixin:
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["matrix_domain"] = settings.MATRIX_DOMAIN
        context["logo_url"] = getattr(settings, "LOGO_URL", None)
        return context


class RateLimitMixin:
    def dispatch(self, request, *args, **kwargs):
        if not settings.TRUST_PROXY:
            ip_address = request.META.get("REMOTE_ADDR")
        else:
            ip_address = request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get(
                "REMOTE_ADDR"
            )

        for block in IPBlock.objects.filter(expires__gt=timezone.now()):
            if ip_network(ip_address) in ip_network(f"{block.network}/{block.netmask}"):
                return render(request, "registration/ratelimit.html", status=429)

        return super().dispatch(request, *args, **kwargs)


class CleanupMixin:
    def dispatch(self, request, *args, **kwargs):
        CleanupCommand().handle()
        return super().dispatch(request, *args, **kwargs)


class LandingPageView(CleanupMixin, TemplateView):
    template_name = "landing_page.html"


class ErrorPageView(TemplateView):
    template_name = "error_page.html"


class CheckUsernameView(RateLimitMixin, ContextMixin, FormView):
    template_name = "registration/username_form.html"
    form_class = UsernameForm
    success_url = reverse_lazy("email_input")

    def form_valid(self, form):
        username = form.cleaned_data["username"]
        try:
            available = synapse_client().username_available(username)
        except Exception as e:
            logger.exception("Synapse username availability check failed")
            form.add_error(
                None,
                "Unable to check username availability right now. Please try again later.",
            )
            return self.form_invalid(form)

        if available:
            self.request.session["username"] = username
            return super().form_valid(form)

        form.add_error("username", "Username is not available.")
        return self.form_invalid(form)


class EmailInputView(RateLimitMixin, ContextMixin, FormView):
    template_name = "registration/email_form.html"
    form_class = EmailForm
    success_url = reverse_lazy("email_sent")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["legal_links"] = settings.LEGAL_LINKS
        context["retention_started"] = settings.RETENTION_STARTED
        context["retention_completed"] = settings.RETENTION_COMPLETED
        return context

    def form_valid(self, form):
        email = form.cleaned_data["email"]

        for block in EmailBlock.objects.all():
            if block.expires and block.expires < timezone.now():
                continue
            if re.match(block.regex, email):
                form.add_error(
                    "email",
                    f"This email address cannot be used to register. "
                    f"{f'Reason: {block.reason}' if block.reason else ''}",
                )
                return self.form_invalid(form)

        if UserRegistration.objects.filter(
            email=email,
            status__in=[
                UserRegistration.STATUS_STARTED,
                UserRegistration.STATUS_REQUESTED,
                UserRegistration.STATUS_APPROVED,
            ],
        ).exists():
            form.add_error(
                "email",
                "There is already a pending or recently accepted registration for this email address. "
                "Please get in touch if you need multiple accounts.",
            )
            return self.form_invalid(form)

        ip_address = self.request.META.get("REMOTE_ADDR")
        if settings.TRUST_PROXY:
            ip_address = self.request.META.get("HTTP_X_FORWARDED_FOR") or ip_address

        if (
            RegistrationEvent.objects.filter(
                ip_address=ip_address,
                type=RegistrationEvent.Type.EMAIL_SUBMITTED,
                occurred_at__gt=timezone.now()
                - timedelta(hours=settings.EMAIL_SUBMISSION_RATE_LIMIT_HOURS),
            ).count()
            >= settings.EMAIL_SUBMISSION_RATE_LIMIT
        ):
            return render(self.request, "registration/ratelimit.html", status=429)

        username = self.request.session.get("username")
        if not username:
            return render(
                self.request, "registration/registration_forbidden.html", status=403
            )

        token = token_urlsafe(32)

        registration = UserRegistration.objects.create(
            username=username,
            email=email,
            token=token,
            ip_address=ip_address,
        )

        log_event(
            registration=registration,
            type=RegistrationEvent.Type.STARTED,
            request=self.request,
            trust_proxy=settings.TRUST_PROXY,
        )

        log_event(
            registration=registration,
            type=RegistrationEvent.Type.EMAIL_SUBMITTED,
            request=self.request,
            trust_proxy=settings.TRUST_PROXY,
            email=email,
        )

        verification_link = self.request.build_absolute_uri(
            reverse_lazy("verify_email", args=[token])
        )

        context = {
            "verification_link": verification_link,
            "matrix_domain": settings.MATRIX_DOMAIN,
            "logo": getattr(settings, "LOGO_URL", None),
            "current_year": datetime.now().year,
        }
        subject = f"[{settings.MATRIX_DOMAIN}] Verify your email address"
        text_content = render_to_string(
            "registration/email/txt/email-verification.txt", context
        )

        msg = EmailMultiAlternatives(
            subject, text_content, settings.DEFAULT_FROM_EMAIL, [email]
        )
        try:
            html_content = render_to_string(
                "registration/email/mjml/email-verification.mjml", context
            )
            msg.attach_alternative(html_content, "text/html")
        except Exception:
            pass

        try:
            msg.send()
            log_event(
                registration=registration,
                type=RegistrationEvent.Type.EMAIL_VERIFICATION_SENT,
                request=self.request,
                trust_proxy=settings.TRUST_PROXY,
            )
        except SMTPRecipientsRefused as e:
            log_event(
                registration=registration,
                type=RegistrationEvent.Type.EMAIL_VERIFICATION_SEND_FAILED,
                request=self.request,
                trust_proxy=settings.TRUST_PROXY,
                error=str(e),
            )
            form.add_error(
                "email",
                "Your email address is invalid, not accepting mail, or blocked by our mail server.",
            )
            registration.delete()
            return self.form_invalid(form)

        return super().form_valid(form)


class VerifyEmailView(RateLimitMixin, View):
    def get(self, request, token):
        try:
            registration = UserRegistration.objects.get(token=token)
        except UserRegistration.DoesNotExist:
            logger.warning("Invalid token: %s", token)
            return render(
                request, "registration/registration_forbidden.html", status=403
            )

        if registration.status != UserRegistration.STATUS_STARTED:
            logger.warning("Invalid status: %s", registration.status)
            return render(
                request, "registration/registration_forbidden.html", status=403
            )

        request.session["registration"] = registration.id
        registration.email_verified = True
        registration.save()

        log_event(
            registration=registration,
            type=RegistrationEvent.Type.EMAIL_VERIFIED,
            request=request,
            trust_proxy=settings.TRUST_PROXY,
        )

        return redirect("complete_registration")


class CompleteRegistrationView(RateLimitMixin, ContextMixin, FormView):
    template_name = "registration/complete_registration.html"
    form_class = RegistrationReasonForm
    success_url = reverse_lazy("registration_complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["legal_links"] = settings.LEGAL_LINKS
        return context

    def dispatch(self, request, *args, **kwargs):
        registration = get_object_or_404(
            UserRegistration, id=request.session.get("registration")
        )

        if (
            registration.status != UserRegistration.STATUS_STARTED
            or not registration.email_verified
        ):
            logger.warning(
                "Invalid status/email_verified: %s/%s",
                registration.status,
                registration.email_verified,
            )
            return render(
                request, "registration/registration_forbidden.html", status=403
            )

        self.registration = registration
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        registration_reason = form.cleaned_data["registration_reason"]
        username = self.registration.username

        # Assert username still available
        try:
            if not synapse_client().username_available(username):
                logger.warning("Username not available at completion: %s", username)
                return render(
                    self.request, "registration/registration_forbidden.html", status=403
                )
        except Exception:
            logger.exception("Synapse username availability check failed at completion")
            return render(self.request, "error_page.html", status=503)

        log_event(
            registration=self.registration,
            type=RegistrationEvent.Type.REGISTRATION_REASON_SUBMITTED,
            request=self.request,
            trust_proxy=settings.TRUST_PROXY,
            length=len(registration_reason or ""),
        )

        self.registration.status = UserRegistration.STATUS_REQUESTED
        self.registration.registration_reason = registration_reason
        self.registration.save()

        log_event(
            registration=self.registration,
            type=RegistrationEvent.Type.REQUESTED,
            request=self.request,
            trust_proxy=settings.TRUST_PROXY,
        )

        # Clear session markers
        for k in ("registration", "username"):
            try:
                self.request.session.pop(k)
            except KeyError:
                pass

        # Email notification to admins
        admin_url = self.request.build_absolute_uri(reverse_lazy("admin:index"))

        context = {
            "matrix_domain": settings.MATRIX_DOMAIN,
            "username": username,
            "email": self.registration.email,
            "registration_reason": registration_reason,
            "logo": getattr(settings, "LOGO_URL", None),
            "admin_url": admin_url,
        }

        subject = f"[{settings.MATRIX_DOMAIN}] Registration Requested"
        text_content = render_to_string(
            "registration/email/txt/new-registration.txt", context
        )
        msg = EmailMultiAlternatives(
            subject,
            text_content,
            settings.DEFAULT_FROM_EMAIL,
            [settings.ADMIN_EMAIL],
        )
        try:
            html_content = render_to_string(
                "registration/email/mjml/new-registration.mjml", context
            )
            msg.attach_alternative(html_content, "text/html")
        except Exception as e:
            logger.error("Failed to render MJML: %s", e)

        try:
            msg.send()
        except SMTPRecipientsRefused as e:
            logger.error("Failed to send email: %s", e)

        # Matrix admin-room notification
        mn = getattr(settings, "MATRIX_NOTIFICATIONS", {}) or {}
        if mn.get("enabled") and mn.get("admin_room", {}).get("room_id"):
            try:
                room_id = mn["admin_room"]["room_id"]
                tmpl = mn["admin_room"].get("message_template", "")
                body = (
                    tmpl.format(
                        username=username,
                        matrix_domain=settings.MATRIX_DOMAIN,
                        email=self.registration.email,
                        reason=registration_reason,
                        admin_url=admin_url,
                    ).strip()
                    or f"New registration requested: @{username}:{settings.MATRIX_DOMAIN}"
                )

                synapse_client().send_room_message_with_join_fallback(room_id, body)
                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.MATRIX_ADMIN_NOTIFIED,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    room_id=room_id,
                )
            except Exception as e:
                logger.exception("Failed to send Matrix admin notification")
                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.MATRIX_ADMIN_NOTIFICATION_FAILED,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    error=str(e),
                )

        return redirect("registration_complete")


class SetPasswordView(RateLimitMixin, ContextMixin, FormView):
    template_name = "registration/set_password.html"
    form_class = PasswordForm
    success_url = reverse_lazy("password_set_success")

    def dispatch(self, request, *args, **kwargs):
        token = kwargs.get("token")
        try:
            registration = UserRegistration.objects.get(token=token)
        except UserRegistration.DoesNotExist:
            return render(
                request, "registration/registration_forbidden.html", status=403
            )

        if registration.status != UserRegistration.STATUS_APPROVED:
            return render(
                request, "registration/registration_forbidden.html", status=403
            )

        log_event(
            registration=registration,
            type=RegistrationEvent.Type.PASSWORD_SET_FORM_OPENED,
            request=request,
            trust_proxy=settings.TRUST_PROXY,
        )

        self.registration = registration
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["username"] = self.registration.username
        return context

    def form_valid(self, form):
        password = form.cleaned_data["password1"]
        username = self.registration.username
        user_id = f"@{username}:{settings.MATRIX_DOMAIN}"

        client = synapse_client()

        # One last username availability check
        try:
            if not client.username_available(username):
                logger.warning("Username not available at set-password: %s", username)
                return render(
                    self.request, "registration/registration_forbidden.html", status=403
                )
        except Exception:
            logger.exception(
                "Synapse username availability check failed at set-password"
            )
            return render(self.request, "error_page.html", status=503)

        # Create user
        try:
            client.create_user(
                username=username, password=password, email=self.registration.email
            )
            log_event(
                registration=self.registration,
                type=RegistrationEvent.Type.USER_CREATED,
                request=self.request,
                trust_proxy=settings.TRUST_PROXY,
                user_id=user_id,
            )
        except SynapseError as e:
            log_event(
                registration=self.registration,
                type=RegistrationEvent.Type.USER_CREATE_FAILED,
                request=self.request,
                trust_proxy=settings.TRUST_PROXY,
                user_id=user_id,
                error=str(e),
            )
            form.add_error(
                None, "Failed to create your account. Please try again later."
            )
            return self.form_invalid(form)

        # Auto-join rooms
        for room in getattr(settings, "AUTO_JOIN", []):
            try:
                client.join_room(room_id=room, user_id=user_id)
                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.AUTOJOIN_OK,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    room_id=room,
                    user_id=user_id,
                )
            except SynapseError as e:
                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.AUTOJOIN_FAIL,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    room_id=room,
                    user_id=user_id,
                    error=str(e),
                )

        # Consent acceptance: submit and verify
        if settings.POLICY_VERSION and settings.FORM_SECRET:
            try:
                consent_ts = submit_and_verify_consent_via_consent_ts(
                    synapse=client,
                    synapse_server=settings.SYNAPSE_SERVER,
                    policy_version=settings.POLICY_VERSION,
                    form_secret=settings.FORM_SECRET,
                    username=username,
                    user_id=user_id,
                    verify_cert=settings.VERIFY_CERT,
                )
                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.CONSENT_OK,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    user_id=user_id,
                    consent_ts=consent_ts,
                    policy_version=settings.POLICY_VERSION,
                )
            except (ConsentError, SynapseError) as e:
                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.CONSENT_FAIL,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    user_id=user_id,
                    error=str(e),
                    policy_version=settings.POLICY_VERSION,
                )

        # Welcome message
        mn = getattr(settings, "MATRIX_NOTIFICATIONS", {}) or {}
        welcome = (mn.get("welcome") or {}) if mn.get("enabled") else {}
        if welcome.get("enabled"):
            try:
                tmpl = welcome.get("message_template", "Welcome!")
                body = tmpl.format(
                    username=username,
                    matrix_domain=settings.MATRIX_DOMAIN,
                ).strip()

                target_room_id = welcome.get("room_id")
                if target_room_id:
                    client.send_room_message(target_room_id, body)
                    where = {"room_id": target_room_id}
                else:
                    # DM: create a direct room with the new user and message them
                    dm_room_id = client.create_dm_room(user_id=user_id)
                    client.send_room_message(dm_room_id, body)
                    where = {"dm_room_id": dm_room_id}

                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.WELCOME_SENT,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    user_id=user_id,
                    **where,
                )
            except Exception as e:
                logger.exception("Failed to send welcome message")
                log_event(
                    registration=self.registration,
                    type=RegistrationEvent.Type.WELCOME_SEND_FAILED,
                    request=self.request,
                    trust_proxy=settings.TRUST_PROXY,
                    user_id=user_id,
                    error=str(e),
                )

        # Mark registration complete
        self.registration.status = UserRegistration.STATUS_COMPLETED
        self.registration.save()

        log_event(
            registration=self.registration,
            type=RegistrationEvent.Type.COMPLETED,
            request=self.request,
            trust_proxy=settings.TRUST_PROXY,
            user_id=user_id,
        )

        return super().form_valid(form)


class PasswordSetSuccessView(TemplateView):
    template_name = "registration/password_set_success.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["matrix_domain"] = settings.MATRIX_DOMAIN
        return context
