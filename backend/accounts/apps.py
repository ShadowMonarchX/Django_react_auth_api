import os
from django.apps import AppConfig
from django.db import connection, OperationalError, IntegrityError
from django.conf import settings

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'
