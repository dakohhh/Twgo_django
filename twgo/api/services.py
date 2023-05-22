import dataclasses
import datetime
from django.db import IntegrityError
import jwt
from typing import TYPE_CHECKING
from django.conf import settings
from . import models
from django.http import JsonResponse
import json

if TYPE_CHECKING:
    from .models import User


@dataclasses.dataclass
class UserDataClass:
    first_name: str
    last_name: str
    email: str
    password: str = None
    id: int = None
    phone_number: str = None
    nationality: str = None
    gender: str = None

    def to_dict(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'password': self.password,
            'id': self.id,
            'phone_number': self.phone_number,
            'nationality': self.nationality,
            'gender': self.gender
        }

    @classmethod
    def from_instance(cls, user: "User") -> "UserDataClass":
        return cls(
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            id=user.id,
            phone_number=user.phone_number,
            nationality=user.nationality,
            gender=user.gender,
        )


class UserDataEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, UserDataClass):
            # Assuming you have a "to_dict" method in UserDataClass that returns a dictionary representation
            return obj.to_dict()
        return super().default(obj)


def create_user(user_dc: UserDataClass) -> "UserDataClass":
    try:
        instance = models.User(
            first_name=user_dc.first_name,
            last_name=user_dc.last_name,
            email=user_dc.email,
            phone_number=user_dc.phone_number,
            nationality=user_dc.nationality,
            gender=user_dc.gender,
        )
        if user_dc.password is not None:
            instance.set_password(user_dc.password)

        instance.save()
        data = {'success': True, 'data': UserDataClass.from_instance(instance)}
        json_data = json.dumps(data, cls=UserDataEncoder).encode('utf-8')
        return JsonResponse(json.loads(json_data))

    except IntegrityError:
        error_message = 'Email address is already taken.'
        return JsonResponse({'success': False, 'error': error_message})


def create_admin(user_dc: UserDataClass) -> "UserDataClass":
    try:
        instance = models.User(
            first_name=user_dc.first_name,
            last_name=user_dc.last_name,
            email=user_dc.email,
            phone_number=user_dc.phone_number,
            nationality=user_dc.nationality,
            gender=user_dc.gender,
            is_staff=True
        )
        if user_dc.password is not None:
            instance.set_password(user_dc.password)

        instance.save()
        data = {'success': True, 'data': UserDataClass.from_instance(instance)}
        json_data = json.dumps(data, cls=UserDataEncoder).encode('utf-8')
        return JsonResponse(json.loads(json_data))

    except IntegrityError:
        error_message = 'Email address is already taken.'
        return JsonResponse({'success': False, 'error': error_message})


def user_email_selector(email: str) -> "User":
    user = models.User.objects.filter(email=email).first()

    return user


def create_token(user_id: int) -> str:
    payload = dict(
        id=user_id,
        exp=datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        iat=datetime.datetime.utcnow(),
    )
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")

    return token
