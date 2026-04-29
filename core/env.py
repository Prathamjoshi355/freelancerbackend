import os
from typing import Iterable

from django.core.exceptions import ImproperlyConfigured

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency in some dev envs
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()

def get_env(name: str, default=None, required: bool = False):
    value = os.getenv(name, default)
    if required and (value is None or str(value).strip() == ""):
        raise ImproperlyConfigured(f"Missing required environment variable: {name}")
    return value


def validate_required_env(names: Iterable[str]):
    missing = [name for name in names if not os.getenv(name)]
    if missing:
        joined = ", ".join(sorted(missing))
        raise ImproperlyConfigured(f"Missing required environment variables: {joined}")
