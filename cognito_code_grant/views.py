import logging

from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.conf.urls import url, include
from django.contrib.auth import login as django_login
from rest_framework.decorators import api_view
from rest_framework.decorators import authentication_classes
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny
from cognito_code_grant.helpers import get_cookie_domain
from cognito_code_grant.authentication import CognitoAuthentication

import requests

TOKEN_TYPES = ['id_token', 'access_token', 'refresh_token']

logger = logging.getLogger(__package__)


@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def login(request):
    app_redirect_url: str = request.query_params.get('redirect_uri', settings.AUTH_COGNITO_REDIRECT_URL)
    id_token: str = request.query_params.get('id_token', '')
    access_token: str = request.query_params.get('access_token', '')
    refresh_token: str = request.query_params.get('refresh_token', '')
    response = HttpResponseRedirect(app_redirect_url)
    tokens: dict = {
        'id_token': id_token,
        'refresh_token': refresh_token,
        'access_token': access_token,
    }
    auth_by_jwt_tokens(request, tokens)
    return response


@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def logout(request):
    app_redirect_url: str = request.query_params.get('redirect_uri', settings.AUTH_COGNITO_REDIRECT_URL)
    response = HttpResponseRedirect(app_redirect_url)
    request.session.flush()
    return response


def include_auth_urls():
    return include([
        url(r'^login/', login),
        url(r'^logout/', logout)
    ])
