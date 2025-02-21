from enum import verify
from pyexpat import model
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import Group, Permission
from rest_framework_simplejwt.tokens import RefreshToken
from .managers import UserManager
from django.utils import timezone

from accounts.managers import UserManager

AUTH_PROVIDERS = {'email': 'email', 'google': 'google'}


class Country(models.Model):
    id = models.BigAutoField(primary_key=True, editable=False)
    name = models.CharField(max_length=25, unique=True)  
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class State(models.Model):
    id = models.BigAutoField(primary_key=True, editable=False)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, related_name="states")
    name = models.CharField(max_length=25)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('country', 'name')  

    def __str__(self):
        return f"{self.name}, {self.country.name}"


class City(models.Model):
    id = models.BigAutoField(primary_key=True, editable=False)
    state = models.ForeignKey(State, on_delete=models.CASCADE, related_name="cities")
    name = models.CharField(max_length=25)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('state', 'name')  # Ensures city names are unique per state

    def __str__(self):
        return f"{self.name}, {self.state.name}, {self.state.country.name}"


class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True, editable=False)
    email = models.EmailField(max_length=255, verbose_name=_("Email Address"), unique=True)
    tc = models.BooleanField()


    country = models.ForeignKey("Country", on_delete=models.CASCADE, null=True, blank=True, related_name="users")
    state = models.ForeignKey("State", on_delete=models.CASCADE, null=True, blank=True, related_name="users")
    city = models.ForeignKey("City", on_delete=models.SET_NULL, null=True, blank=True, related_name="users")

    first_name = models.CharField(max_length=100, default="")
    last_name = models.CharField(max_length=100, default="")
    phone_number = models.BigIntegerField(unique=True, null=True, blank=True)

    # is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    is_verified = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    auth_provider = models.CharField(max_length=50, blank=False, null=False, default="email")

    groups = models.ManyToManyField(Group, related_name="custom_user_groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_user_permissions", blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['tc']

    objects = UserManager()

    def tokens(self):
        """Generate access and refresh tokens."""
        refresh = RefreshToken.for_user(self)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

    def __str__(self):
        return self.email


class OneTimePassword(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(default=timezone.now) 

    def __str__(self):
        return f"{self.user.first_name} - OTP Code"
