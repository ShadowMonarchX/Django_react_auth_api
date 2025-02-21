from unicodedata import name
from django.urls import path
from .views import (
        RegisterView, 
        VerifyUserEmail , 
        LoginUserView , 
        LogoutApiView , 
        AdditionalUserDetailsView , 
        CountryListView , 
        StateListView , 
        CityFilterView , 
        PasswordResetConfirm,
        SetNewPasswordView ,
        PasswordResetRequestView
        )
from rest_framework_simplejwt.views import (TokenRefreshView,)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyUserEmail.as_view(), name='verify'),
    path('AdditionalUser/', AdditionalUserDetailsView.as_view(), name='AdditionalUser'),
    path('login/', LoginUserView.as_view(), name='login-user'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirm.as_view(), name='reset-password-confirm'),
    path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),
    path('logout/', LogoutApiView.as_view(), name='logout'),
    path('countries/', CountryListView.as_view(), name='country-list'),
    path('states/', StateListView.as_view(), name='state-list'),
    path('cities/', CityFilterView.as_view(), name='city-filter'),
    ]