import uuid
import secrets

from typing import Type, Union
from django.db.models import Model
from .models import OTP, User




def fetchone(klass:Type[Union[Model, User, OTP]], *args, **kwargs)-> Union[User, OTP, None]:
    try:
        return klass.objects.get(*args, **kwargs)
    except klass.DoesNotExist:
        return None
    except Exception as e:
        raise e
    




def generate_hex(length:int=15):
    random_hex = secrets.token_hex(length)

    return random_hex
