from rest_framework import authentication, exceptions
from django.conf import settings
import jwt

from . import models


class CustomUserAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        token = self.get_token_from_header(request)

        if not token:
            return None

        try:
            payload = jwt.decode(
                token, settings.JWT_SECRET, algorithms=["HS256"])
        except jwt.exceptions.InvalidTokenError:
            raise exceptions.AuthenticationFailed("Unauthorized")

        user = models.User.objects.filter(id=payload["id"]).first()

        return (user, None)

    def get_token_from_header(self, request):
        header = request.META.get("HTTP_AUTHORIZATION")

        if header and header.startswith("Bearer "):
            return header.split(" ")[1]

        return None
