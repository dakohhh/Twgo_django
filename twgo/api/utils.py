import requests
import secrets
from typing import Type, Union
from django.db.models import Model
from .models import OTP, User, Funds, Project
from django.db.models.query import QuerySet





def fetchone(klass:Type[Union[Model, User, OTP, Funds, Project]], *args, **kwargs) -> Union[User, OTP, Funds, Project, None]:
    try:
        return klass.objects.get(*args, **kwargs)
    except klass.DoesNotExist:
        return None
    except Exception as e:
        raise e




def fetch_filter(klass:Type[Union[Model, User, OTP, Funds, Project]], *args, **kwargs) -> Union[QuerySet, None]:
    try:
        return klass.objects.filter(*args, **kwargs)
    except klass.DoesNotExist:
        return None
    except Exception as e:
        raise e




def generate_hex(length:int=15) -> str:
    random_hex = secrets.token_hex(length)

    return random_hex



def get_conversion_rate(base_currency, target_currency) -> float:
    # Make a request to the currency exchange rate API
    api_url = f"https://api.exchangerate-api.com/v4/latest/{base_currency}"
    response = requests.get(api_url)
    
    if response.status_code == 200:
        data = response.json()
        rates = data.get("rates")
        conversion_rate = rates.get(target_currency)
        return conversion_rate
    
    return None