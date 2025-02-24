from ast import Expression
import re
from datetime import timedelta
from django.utils import timezone
from multiprocessing import context
from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from accounts.models import OneTimePassword, User ,City,State,Country

from accounts.serializers import (
    UserRegisterSerializer,
    AdditionalUserDetailsSerializer,
    LoginSerializer,
    LogoutUserSerializer,
    CountrySerializer,
    CitySerializer,
    StateSerializer,
    PasswordResetRequestSerializer,
    PasswordResetTokenGenerator,
    SetNewPasswordSerializer
)
from .utils import send_generated_otp_to_email
from rest_framework.permissions import AllowAny , IsAuthenticated
from django.utils.http import urlsafe_base64_decode
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .permissions import  IsOwnerOrReadOnly
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.models import AnonymousUser


class RegisterView(APIView):
    permission_classes = [AllowAny]
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        email = user_data.get('email')
        password = user_data.get('password')
        print(email)
        # print(password)
        if not email:
            return Response({
                "status": "failure",
                "message": "Email is required.",
                "error": "Missing email field."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not password :
            return Response({
                "status": "failure",
                "message": "Password is required.",
                "error": "Missing Password field."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not self.is_valid_email(email):
            return Response({
                "status": "failure",
                "message": "Invalid email format.",
                "error": "Invalid email."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # if not self.is_valid_password(password) :
        #     return Response({
        #         "status": "failure",
        #         "message": "Invalid password format.",
        #         "error": "Invalid Password."
        #     }, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():

            return Response({
                "status": "failure",
                "message": "This email is already registered.",
                "error": "Email already exists."
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class(data=user_data)

        if serializer.is_valid():

            try:
                user = serializer.save()

                send_generated_otp_to_email(user.email, request)

                return Response({
                    "status": "success",
                    "message": "OTP sent to your email for verification.",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)
            
            except Exception as e:

                return Response({
                    "status": "failure",
                    "message": "User creation failed.",
                    "error": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response({
            "status": "failure",
            "message": "Invalid data provided.",
            "error": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def is_valid_email(self, email):
        # email validestion

        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

        return re.match(email_regex, email) is not None
    
    def is_valid_password(self,password) :

        # min length is 6 and max length is 20
        # at least include a digit number,
        # at least a upcase and a lowcase letter
        # at least a special characters

        password_regex = r"('^(?=\S{6,20}$)(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])')"

        return re.match(password_regex,password)



class VerifyUserEmail(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            passcode = request.data.get('otp')
            user_pass_obj = OneTimePassword.objects.get(otp=passcode)
            user = user_pass_obj.user
            otp_creation_time = user_pass_obj.created_at 

            if timezone.now() - otp_creation_time > timedelta(minutes=2):
                return Response({'message': 'OTP expired.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if not user.is_verified:
                user.is_verified = True
                user.save()
                refresh = RefreshToken.for_user(user)

                return Response({
                    'message': 'Account email verified successfully.',
                    'data': {
                        'email': user.email,
                        'is_verified': user.is_verified,
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh),
                        'message': 'This is user Token BY Send Backend'
                    }
                }, status=status.HTTP_200_OK)

            return Response({'message': 'User is already verified.'}, status=status.HTTP_204_NO_CONTENT)

        except OneTimePassword.DoesNotExist:
            return Response({'message': 'Invalid passcode or OTP expired.'}, status=status.HTTP_400_BAD_REQUEST)


        

class LoginUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        
        serializer = LoginSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            return Response(
                {
                    'message' : 'You Are Login sucessfully.',
                    'data' : serializer.validated_data
                }, status=status.HTTP_200_OK)


        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class PasswordResetRequestView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def is_valid_email(self, email):
        # email validestion
        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

        return re.match(email_regex, email) is not None

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        user_data = request.data
        email = user_data.get('email')

        if not email:
            return Response({
                "status": "failure",
                "message": "Email is required.",
                "error": "Missing email field."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not self.is_valid_email(email):
            return Response({
                "status": "failure",
                "message": "Invalid email format.",
                "error": "Invalid email."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if serializer.is_valid():
            email = serializer.validated_data.get('email')

            try :
                user = User.objects.get(email=email)
                # print("user :",user)
                return Response({'message': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
            
            except User.DoesNotExist:
                return Response({'message': 'User with that email  not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    



class PasswordResetConfirm(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64=None, token=None):
        if not uidb64 or not token:
            return Response({'message': 'Invalid request. Missing parameters.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            # print(user_id)
            # print(user)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message': 'Token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({
                'success': True,
                'message': 'Credentials are valid',
                'uidb64': uidb64,
                'token': token
            }, status=status.HTTP_200_OK)

        except (ValueError, User.DoesNotExist):
            return Response({'message': 'Token is invalid or has expired'}, status=status.HTTP_401_UNAUTHORIZED)




class SetNewPasswordView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordSerializer

    def is_valid_password(self, new_password):
        # Min length 6 and max length 20
        # At least one digit
        # At least one uppercase and one lowercase letter
        # At least one special character

        password_regex = r"^(?=\S{6,20}$)(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9\s])"
        
        return re.match(password_regex, new_password)

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        new_password = request.data.get('new_password')

        if not self.is_valid_password(new_password):
            return Response({
                'success': False,
                'message': "Password must contain at least one digit, one uppercase letter, one lowercase letter, and one special character."
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'success': True,
            'message': "Password reset is successful."
        }, status=status.HTTP_200_OK)





class LogoutApiView(GenericAPIView):
    serializer_class=LogoutUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
 

    

class AdditionalUserDetailsView(APIView):
    serializer_class = AdditionalUserDetailsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerOrReadOnly]

    def get_serializer_context(self):
        return {"request": self.request}

    def is_valid_phone_number(self, phone_number):

        return phone_number.isdigit() and len(phone_number) == 10

    def is_valid_data(self, first_name, last_name):

        return all(3 <= len(name) <= 25 for name in (first_name, last_name))
    
    def patch(self, request):
        if isinstance(request.data, AnonymousUser):
            return Response({
                'status': 'error',
                'message': 'User is not authenticated. Please log in.',
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user_update_data = request.data
            phone_number = user_update_data.get("phone_number")
            first_name = user_update_data.get("first_name")
            last_name = user_update_data.get("last_name")

            if not phone_number:
                return Response({
                    "status": "failure",
                    "message": "Phone number is required.",
                    "error": "Missing phone number field."
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not first_name :
                return Response({
                    "status" : "faolure",
                    "message": "First Name is required.",
                    "error": "Missing First Name field."
                },status=status.HTTP_400_BAD_REQUEST)
            
            if not last_name :
                return Response({
                    "status" : "faolure",
                    "message": "Last Name is required.",
                    "error": "Missing Last Name field."
                },status=status.HTTP_400_BAD_REQUEST)
            

            if not self.is_valid_phone_number(phone_number):
                return Response({
                    "status": "failure",
                    "message": "Invalid phone number format.",
                    "error": "Invalid phone number."
                }, status=status.HTTP_400_BAD_REQUEST)

            if not self.is_valid_data(first_name,last_name) :
                 return Response({
                    "status": "failure",
                    "message": "Invalid First Name or Last Name format.",
                    "error": "Invalid First Name or Last Name."
                }, status=status.HTTP_400_BAD_REQUEST)

                

            user = request.user  

            
            if not user:
                return Response({
                    'status': 'error',
                    'message': 'User not found.',
                }, status=status.HTTP_404_NOT_FOUND)

            self.check_object_permissions(request, user) 

            serializer = self.serializer_class(instance=user, data=request.data, partial=True, context=self.get_serializer_context())
            serializer.is_valid(raise_exception=True)

            updated_user = serializer.save()

            return Response({
                'status': 'success',
                'message': 'Personal information updated successfully.',
                'data': self.serializer_class(updated_user).data,
            }, status=status.HTTP_200_OK)

        except InvalidToken:
            return Response({
                'status': 'error',
                'message': 'Token has expired or is invalid. Please log in again.',
            }, status=status.HTTP_401_UNAUTHORIZED)


class CountryListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            countries = Country.objects.all()
            if not countries.exists():
                return Response({"message": "No countries found."}, status=status.HTTP_404_NOT_FOUND)

            serializer = CountrySerializer(countries, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StateListView(GenericAPIView):
    permission_classes = [AllowAny]  
    serializer_class = StateSerializer

    def get(self, request):
        country_id = request.query_params.get('country')

        if not country_id:
            return Response({"message": "Country ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not Country.objects.filter(id=country_id).exists():
            return Response({"message": "Invalid Country ID."}, status=status.HTTP_404_NOT_FOUND)

        states = State.objects.filter(country_id=country_id)
        if not states.exists():
            return Response({"message": "No states found for this country."}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(states, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CityFilterView(GenericAPIView):
    permission_classes = [AllowAny]  
    serializer_class = CitySerializer

    def get(self, request):
        state_id = request.query_params.get('state')

        if not state_id:
            return Response({"message": "State ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not State.objects.filter(id=state_id).exists():
            return Response({"message": "Invalid State ID."}, status=status.HTTP_404_NOT_FOUND)

        cities = City.objects.filter(state_id=state_id)
        if not cities.exists():
            return Response({"message": "No cities found for this state."}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(cities, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)