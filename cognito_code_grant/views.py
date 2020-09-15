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
    code: str = request.query_params.get('code', '')
    state: str = request.query_params.get('state')
    if code:
        tokens: dict = get_tokens_by_code(code, state)
    else:
        id_token: str = request.query_params.get('id_token', '')
        access_token: str = request.query_params.get('access_token', '')
        refresh_token: str = request.query_params.get('refresh_token', '')
        tokens: dict = {
            'id_token': id_token,
            'refresh_token': refresh_token,
            'access_token': access_token,
        }

    response = HttpResponseRedirect(state or app_redirect_url)
    for token_type in TOKEN_TYPES:
        request.session[token_type] = tokens[token_type]
    auth = CognitoAuthentication()
    user = auth.authenticate(request)
    django_login(request, user[0])
    return response


def get_tokens_by_code(code, redirect_uri):
    cognito_reply = requests.post(settings.AUTH_COGNITO_CODE_GRANT_URL, data={
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': settings.AUTH_COGNITO_CLIENT_ID,
        'redirect_uri': redirect_uri
    })

    try:
        cognito_reply.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.warning("Auth request failed with status %s: %s",
                       e.response.status_code, e.response.content)
        return HttpResponse('Unauthorized', status=401)
    return cognito_reply.json()


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
        url(r'^login/', login, name="cognito-login"),
        url(r'^logout/', logout, name="cognito-logout")
    ])
