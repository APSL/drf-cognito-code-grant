"""Django settings for tests."""

test_settings = {
    'SECRET_KEY': "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    'LOGGING_CONFIG': None,  # avoids spurious output in tests
    'INSTALLED_APPS': [
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        "django.contrib.messages",
        "django.contrib.staticfiles",
        "cognito_code_grant",
        "tests",
    ],
    'MIDDLEWARE': [
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ],
    'ROOT_URLCONF': "tests.urls",
    'CACHES': {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
    },
    'DJANGO_DEBUG': True,
    'DATABASES': {"default": {"ENGINE": "django.db.backends.sqlite3"}},

    'AUTH_COGNITO_JWKS_URL': 'https://jwks.url/jwks.json',
    'AUTH_COGNITO_CODE_GRANT_URL': 'https://your_cognito_url.com/oauth2/token',
    'AUTH_COGNITO_CLIENT_ID': 'APPCLIENTID'
}