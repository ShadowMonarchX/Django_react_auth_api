from pathlib import Path
import environ
import os

env = environ.Env(
    DEBUG=(bool, False)
)
environ.Env.read_env()
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# Get secret key from .env file
SECRET_KEY = env('SECRET_KEY')

# Set debug mode
DEBUG = env.bool('DEBUG', default=False)

ALLOWED_HOSTS = []


# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',  # Ensure sessions app is included
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'corsheaders',
    'accounts',
    'rest_framework_simplejwt.token_blacklist',
    'rest_framework.authtoken',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "user_auth",
        "USER": "root",
        "PASSWORD": env('PASSWORD'),
        "HOST": "localhost",
        "PORT": "3306",
    }
}
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',  # Ensure SessionMiddleware is included
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

SESSION_ENGINE = "django.contrib.sessions.backends.db"  # Use database-backed sessions
SESSION_COOKIE_NAME = "otp_session"  # Custom session cookie name
SESSION_COOKIE_AGE = 120  # Session expires after 2 minutes
SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # Session expires when the browser is closed
SESSION_SAVE_EVERY_REQUEST = True  # Save the session on every request
SESSION_COOKIE_SAMESITE = 'None'  # Allow cross-site requests
SESSION_COOKIE_SECURE = False  # Set to True in production (requires HTTPS)
SESSION_COOKIE_HTTPONLY = False  # Allow JavaScript to access the session cookie

CORS_ALLOW_ALL_ORIGINS = True

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

AUTH_USER_MODEL = "accounts.User"

# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'



EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# Looking to send emails in production? Check out our Email API/SMTP product!
EMAIL_HOST = 'sandbox.smtp.mailtrap.io'
EMAIL_HOST_USER = env('EMAIL_HOST_USER')   # Correct
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')  # Correct
EMAIL_PORT = '2525'
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER  # Default sender email




PASSWORD_RESET_TIMEOUT = 900

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS settings for cross-origin requests
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  
    "http://127.0.0.1:5173",  
]

CORS_ALLOW_CREDENTIALS = True  # Allow credentials (cookies, etc.) for cross-origin requests

CORS_ALLOW_HEADERS = [
    'content-type', 'authorization', 'accept', 'origin', 'x-requested-with',
]


# Optional settings for preflight requests, which can cache the response for a specified time
CORS_PREFLIGHT_MAX_AGE = 86400  # Cache preflight responses for 1 day

# Additional CORS settings if required, like specific methods or exposing headers
CORS_ALLOW_METHODS = [
    'GET', 'POST', 'OPTIONS', 'PUT', 'DELETE', 'PATCH'
]
