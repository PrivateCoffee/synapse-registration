from typing import Any

from django.http import HttpRequest

from .models import RegistrationEvent, UserRegistration


def _client_ip(request: HttpRequest | None, trust_proxy: bool) -> str | None:
    if not request:
        return None
    ip = request.META.get("REMOTE_ADDR")
    if trust_proxy:
        ip = request.META.get("HTTP_X_FORWARDED_FOR") or ip
    return ip


def log_event(
    *,
    registration: UserRegistration,
    type: str,
    request: HttpRequest | None = None,
    actor=None,
    trust_proxy: bool = False,
    **data: Any,
) -> RegistrationEvent:
    ip = _client_ip(request, trust_proxy)
    return RegistrationEvent.objects.create(
        registration=registration,
        type=type,
        actor=actor,
        ip_address=ip,
        data=data or {},
    )