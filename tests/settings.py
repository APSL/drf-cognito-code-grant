"""Django settings for tests."""
import tempfile
import os

SECRET_KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",

DATABASES = {"default": {
    "ENGINE": "django.db.backends.sqlite3",
    'NAME': os.path.join(tempfile.gettempdir(), "test")
}}

ROOT_URLCONF = "tests.urls"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "cognito_code_grant",
    "tests",
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
}

DJANGO_DEBUG = True,

SHARED_TOKENS = False
SHARED_TOKENS_DOMAIN = None


AUTH_COGNITO_JWKS_URL = 'https://jwks.url/jwks.json',
AUTH_COGNITO_CODE_GRANT_URL = 'https://your_cognito_url.com/oauth2/token',
AUTH_COGNITO_CLIENT_ID = 'APPCLIENTID'
