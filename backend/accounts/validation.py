import re
from rest_framework.response import Response
from rest_framework import status
from accounts.models import User

def RegisterValidation(request):
    user_data = request.data
    email = user_data.get('email')
    password = user_data.get('password')

    if not email:
        return Response({
            "status": "failure",
            "message": "Email is required.",
            "error": "Missing email field."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not password:
        return Response({
            "status": "failure",
            "message": "Password is required.",
            "error": "Missing password field."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not is_valid_email(email):
        return Response({
            "status": "failure",
            "message": "Invalid email format.",
            "error": "Invalid email."
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if User.objects.filter(email=email).exists():

            return Response({
                "status": "failure",
                "message": "This email is already registered.",
                "error": "Email already exists."
            }, status=status.HTTP_400_BAD_REQUEST)


def AdditionalUserDetailsValidation(request):
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

    if not first_name:
        return Response({
            "status": "failure",
            "message": "First Name is required.",
            "error": "Missing First Name field."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not last_name:
        return Response({
            "status": "failure",
            "message": "Last Name is required.",
            "error": "Missing Last Name field."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not is_valid_phone_number(phone_number):
        return Response({
            "status": "failure",
            "message": "Invalid phone number format.",
            "error": "Invalid phone number."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not is_valid_data(first_name, last_name):
        return Response({
            "status": "failure",
            "message": "Invalid First Name or Last Name format.",
            "error": "Invalid First Name or Last Name."
        }, status=status.HTTP_400_BAD_REQUEST)

    user = request.user
    if not user:
        return Response({
            "status": "error",
            "message": "User not found."
        }, status=status.HTTP_404_NOT_FOUND)

def PasswordResetValidation(request) :
    user_data = request.data
    email = user_data.get('email')

    if not email:
        return Response({
                "status": "failure",
                "message": "Email is required.",
                "error": "Missing email field."
        }, status=status.HTTP_400_BAD_REQUEST)
        
    if not is_valid_email(email):
        return Response({
            "status": "failure",
            "message": "Invalid email format.",
            "error": "Invalid email."
        }, status=status.HTTP_400_BAD_REQUEST)
    
def is_valid_email(email):

    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

    return re.match(email_regex, email) is not None

def is_valid_password(password):

    password_regex = r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?\d)(?=.*?[^\w\s]).{6,20}$"

    return re.match(password_regex, password) is not None

def is_valid_phone_number(phone_number):

    return phone_number.isdigit() and len(phone_number) == 10

def is_valid_data(first_name, last_name):

    return all(3 <= len(name) <= 25 for name in (first_name, last_name))
