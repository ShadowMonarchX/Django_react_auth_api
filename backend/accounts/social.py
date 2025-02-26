import requests
import jwt
from django.contrib.auth import get_user_model
from rest_framework.exceptions import AuthenticationFailed

User = get_user_model()

class Google:
    @staticmethod
    def validate(access_token):

        response = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        user_data = response.json()
        print("Google API Response:", user_data)  
        if response.status_code != 200 or "error" in user_data:
            return {"error": "Invalid token"}

        return user_data

    @staticmethod
    def get_id_token_info(id_token):
        """Decode the ID token"""
        try:
            decoded_token = jwt.decode(id_token, options={"verify_signature": False})
            return decoded_token
        except jwt.DecodeError:
            raise AuthenticationFailed("Invalid ID Token")

def register_social_user(provider, access_token, id_token):
   
    if provider == "google":
        user_data = Google.validate(access_token)  
        decoded_token = Google.get_id_token_info(id_token)  
    else:
        raise AuthenticationFailed("Invalid provider")

    email = decoded_token.get("email") 
    if not email:
        raise AuthenticationFailed("Email not found in ID token")

    user, created = User.objects.get_or_create(
        email=email, defaults={"auth_provider": provider, "is_verified": True}
    )

    return {
        "email": user.email,
        "access_token": user.tokens().get("access"),
        "refresh_token": user.tokens().get("refresh"),
    }




# class Netflix:
#     CLIENT_ID = settings.NETFLIX_CLIENT_ID
#     CLIENT_SECRET = settings.NETFLIX_CLIENT_SECRET
#     REDIRECT_URI = settings.NETFLIX_REDIRECT_URI
#     TOKEN_URL = "https://api.netflix.com/oauth/token"
#     USER_INFO_URL = "https://api.netflix.com/v1/me"

#     @staticmethod
#     def exchange_code_for_token(code):
#         data = {
#             "client_id": Netflix.CLIENT_ID,
#             "client_secret": Netflix.CLIENT_SECRET,
#             "redirect_uri": Netflix.REDIRECT_URI,
#             "code": code,
#             "grant_type": "authorization_code",
#         }
#         response = requests.post(Netflix.TOKEN_URL, data=data)
#         return response.json().get("access_token") if response.status_code == 200 else None

#     @staticmethod
#     def get_user_info(access_token):
#         headers = {"Authorization": f"Bearer {access_token}"}
#         response = requests.get(Netflix.USER_INFO_URL, headers=headers)
#         return response.json() if response.status_code == 200 else None


