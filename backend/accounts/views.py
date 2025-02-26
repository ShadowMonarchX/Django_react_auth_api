import email
from accounts.models import *
from accounts.serializers import *
from accounts.validation import *
from accounts.utils import send_generated_otp_to_email
from accounts.social import register_social_user
from accounts.permissions import  IsOwnerOrReadOnly

from django.utils.http import urlsafe_base64_decode
from django.http import JsonResponse
from django.utils.encoding import smart_str
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import render
from django.utils.decorators import method_decorator


from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny , IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django_ratelimit.decorators import ratelimit




from datetime import datetime
from multiprocessing import context

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        validation_error = RegisterValidation(request)
        
        if validation_error:
            return validation_error 
        serializer = UserRegisterSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                "status": "failure",
                "message": "Invalid data provided.",
                "error": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')

        if User.objects.filter(email=email).exists():
            return Response({
                "status": "failure",
                "message": "This email is already registered."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = serializer.save()
            user.is_verified = False
            user.save()

            if send_generated_otp_to_email(user.email, request):
                return Response({
                    "status": "success",
                    "message": "OTP sent to your email for verification.",
                    "data": {"email": user.email}
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "status": "failure",
                    "message": "Failed to send OTP."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "status": "failure",
                "message": "User creation failed.",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyUserEmail(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        otp = request.data.get('otp')
        # print(f"Received OTP: {otp}")

        session_otp = request.session.get('otp')
        session_email = request.session.get('otp_email')
        otp_expiry = request.session.get('otp_expiry')

        # print(f"Session OTP: {session_otp}")
        # print(f"Session Email: {session_email}")
        # print(f"OTP Expiry: {otp_expiry}")

        if not otp or not session_otp or not session_email or not otp_expiry:
            return Response({
                "status": "failure",
                "message": "Invalid OTP or session expired."
            }, status=status.HTTP_400_BAD_REQUEST)

       
        try:
            otp_expiry_dt = datetime.strptime(otp_expiry, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return Response({
                "status": "failure",
                "message": "Invalid session expiry format."
            }, status=status.HTTP_400_BAD_REQUEST)

      
        if datetime.now() > otp_expiry_dt:
            return Response({
                "status": "failure",
                "message": "OTP expired."
            }, status=status.HTTP_400_BAD_REQUEST)

      
        if otp == session_otp:
            try:
                user = User.objects.get(email=session_email)
                user.is_verified = True
                user.save()

               
                request.session.pop('otp', None)
                request.session.pop('otp_email', None)
                request.session.pop('otp_expiry', None)
                request.session.save() 

               
                refresh = RefreshToken.for_user(user)
                return Response({
                    "status": "success",
                    "message": "Email verified successfully.",
                    "data": {
                        "email": user.email,
                        "access_token": str(refresh.access_token),
                        "refresh_token": str(refresh)
                    }
                }, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({
                    "status": "failure",
                    "message": "User not found."
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "status": "failure",
            "message": "Invalid OTP."
        }, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(ratelimit(key='user', rate='3/h', method='POST'))
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({
                "status": "failure",
                "message": "Email is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                "status": "failure",
                "message": "User with this email does not exist."
            }, status=status.HTTP_404_NOT_FOUND)

        if user.is_verified:
            return Response({
                "status": "failure",
                "message": "User is already verified."
            }, status=status.HTTP_400_BAD_REQUEST)


        if send_generated_otp_to_email(email, request):
            return Response({
                "status": "success",
                "message": "OTP resent to your email.",
                "data": {"email": email}
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "status": "failure",
                "message": "Failed to resend OTP."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdditionalUserDetailsView(APIView):
    serializer_class = AdditionalUserDetailsSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerOrReadOnly]

    def get_serializer_context(self):
        return {"request": self.request}
    
    def patch(self, request):
        if isinstance(request.data, AnonymousUser):
            return Response({
                'status': 'error',
                'message': 'User is not authenticated. Please log in.',
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            validation_error = AdditionalUserDetailsValidation(request)
        
            if validation_error:
                return validation_error
             
            user = request.user
            self.check_object_permissions(request,user) 

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

class LoginUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = User.objects.filter(email=email).first()

        if not user or not user.check_password(password):
            return Response({
                "status": "failure",
                "message": "Invalid credentials."
            }, status=status.HTTP_400_BAD_REQUEST)

        if not user.is_verified:
            return Response({
                "status": "failure",
                "message": "Email not verified."
            }, status=status.HTTP_400_BAD_REQUEST)

        refresh = RefreshToken.for_user(user)
        return Response({
            "status": "success",
            "message": "Login successful.",
            "data": {
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
            }
        }, status=status.HTTP_200_OK)

class PasswordResetRequestView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})

        validation_error = PasswordResetValidation(request)
        
        if validation_error:
            return validation_error
        
        if serializer.is_valid():
            email = serializer.validated_data.get('email')

            try :
                user = User.objects.get(email=email)

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

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        new_password = request.data.get('new_password')

        if not is_valid_password(new_password):
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


class GoogleSignInView(APIView):
    def post(self, request, *args, **kwargs):
        access_token = request.data.get("access_token")
        id_token = request.data.get("id_token") 

        if not access_token or not id_token:
            return Response(
                {"error": "Both access_token and id_token are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_data = register_social_user("google", access_token, id_token)  
        return Response(user_data, status=status.HTTP_200_OK)



class GoogleAuthView(APIView):
    def post(self, request):
        return JsonResponse({"message": "Google Sign-in API working"})



# class NetflixOauthSignInView(APIView):
#     serializer_class = NetflixLoginSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
        
#         access_token = serializer.validated_data['code']
#         user_data = register_social_user("netflix", access_token)

#         return Response(user_data, status=status.HTTP_200_OK)