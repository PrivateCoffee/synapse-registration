import logging
import traceback

from django.core.mail import mail_admins

logger = logging.getLogger("synapse_registration")


class ErrorHandlingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        # Log the error
        error_message = f"Exception in {request.path}: {exception!s}"
        logger.error(error_message, exc_info=True)  # noqa: LOG014

        # Send an email to admins
        try:
            tb = traceback.format_exc()
            subject = f"Error on {request.path}"
            message = f"An error occurred on {request.path}:\n\n{error_message}\n\nTraceback:\n{tb}"
            mail_admins(subject, message, fail_silently=True)
        except Exception:
            logger.exception("Failed to send admin notification email")

        # Let Django continue with its normal exception handling
