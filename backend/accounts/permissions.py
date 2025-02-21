from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError

class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False 

        token_str = auth_header.split(" ")[1]
        try:
            token = AccessToken(token_str)
            user = token.payload.get('user_id')  
        except (TokenError, IndexError):
            raise PermissionDenied("Invalid or expired token. Please log in again.")
        
        return user == obj.id  

