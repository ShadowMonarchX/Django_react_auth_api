import json
from dataclasses import field
from accounts.models import User,City,State,Country
from rest_framework import serializers
from rest_framework.response import Response
from string import ascii_lowercase, ascii_uppercase
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework import status

# print(RefreshToken)
# print(TokenError)

class CitySerializer(serializers.ModelSerializer):
    class Meta:
        model = City
        fields = '__all__'  



class StateSerializer(serializers.ModelSerializer):
    country = serializers.StringRelatedField()  
    class Meta:
        model = State
        fields = ['id', 'name', 'country']



class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Country
        fields = ['id', 'name']




class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    class Meta:
        model=User
        fields = ['email','password','tc']

    def create(self, validated_data):
        user= User.objects.create_user(
            email=validated_data['email'],
            password=validated_data.get('password'),
            tc = validated_data.get('tc')
            )
        return user
    
    



class AdditionalUserDetailsSerializer(serializers.ModelSerializer):
    city_id = serializers.PrimaryKeyRelatedField(
        queryset=City.objects.all(), source='city', write_only=True
    )
    state_id = serializers.PrimaryKeyRelatedField(
        queryset=State.objects.all(), source='state', write_only=True
    )
    country_id = serializers.PrimaryKeyRelatedField(
        queryset=Country.objects.all(), source='country', write_only=True
    )

    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone_number', 'country_id', 'state_id', 'city_id', 'access_token', 'refresh_token']

    def validate(self, attrs):
        if not attrs.get('phone_number'):
            raise serializers.ValidationError({"phone_number": "Phone number is required."})
        return attrs

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        instance.phone_number = validated_data.get("phone_number", instance.phone_number)
        instance.city = validated_data.get("city", instance.city)
        instance.state = validated_data.get("state", instance.state)
        instance.country = validated_data.get("country", instance.country)
        instance.save()
        try:
            tokens = instance.tokens()  
        except InvalidToken:
            return Response({
                'status': 'error',
                'message': 'Token has expired or is invalid. Please log in again.',
            }, status=status.HTTP_401_UNAUTHORIZED)

        return {
            "first_name": instance.first_name,
            "last_name": instance.last_name,
            "phone_number": instance.phone_number,
            "access_token": tokens["access"],
            "refresh_token": tokens["refresh"],
        }





        

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6)
    password=serializers.CharField(max_length=68, write_only=True)
    access_token=serializers.CharField(max_length=255, read_only=True)
    refresh_token=serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'access_token', 'refresh_token']


    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request=self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("invalid credential try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        tokens=user.tokens()
        return {
            'email':user.email,
            "access_token":str(tokens.get('access')),
            "refresh_token":str(tokens.get('refresh'))
        }


class LogoutUserSerializer(serializers.Serializer):
    refresh_token=serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')

        return attrs

    def save(self, **kwargs):
        try:
            token=RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')
        


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user= User.objects.get(email=email)
            uidb64=urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            request=self.context.get('request')
            current_site=get_current_site(request).domain
            relative_link =reverse('reset-password-confirm', kwargs={'uidb64':uidb64, 'token':token})
            abslink=f"http://{current_site}{relative_link}"
            print(abslink)
            email_body=f"Hi {user.first_name} use the link below to reset your password {abslink}"
            data={
                'email_body':email_body, 
                'email_subject':"Reset your Password", 
                'to_email':user.email
                }
            send_normal_email(data)

        return super().validate(attrs)

    
class SetNewPasswordSerializer(serializers.Serializer):
    password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password=serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64=serializers.CharField(min_length=1, write_only=True)
    token=serializers.CharField(min_length=3, write_only=True)

    class Meta:
        fields = ['password', 'confirm_password', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')
            password=attrs.get('password')
            confirm_password=attrs.get('confirm_password')

            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("reset link is invalid or has expired", 401)
            if password != confirm_password:
                raise AuthenticationFailed("passwords do not match")
            user.set_password(password)
            user.save()
            return user
        except Exception as e:
            return AuthenticationFailed("link is invalid or has expired")


    
class LogoutUserSerializer(serializers.Serializer):
    refresh_token=serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')

        return attrs

    def save(self, **kwargs):
        try:
            token=RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')

    

    
    