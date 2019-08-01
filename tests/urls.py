from django.urls import path
from cognito_code_grant.views import include_auth_urls

urlpatterns = [
    path('auth/', include_auth_urls())
]