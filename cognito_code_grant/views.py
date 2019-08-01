from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import path, include
from rest_framework.decorators import api_view
from rest_framework.decorators import authentication_classes

import requests

TOKEN_TYPES = ['id_token', 'access_token', 'refresh_token']


@api_view(['GET'])
@authentication_classes([])
def login(request):
    auth_redirect_url: str = request.build_absolute_uri().split('?')[0]
    # since the app is running in container, no way to know its on ssl
    auth_redirect_url = auth_redirect_url.replace('http', 'https')
    auth_code: str = request.query_params.get('code', '')
    app_redirect_url: str = request.query_params.get('state', '')

    cognito_reply = requests.post(settings.AUTH_COGNITO_CODE_GRANT_URL, data={
        'grant_type': 'authorization_code',
        'code': auth_code,
        'client_id': settings.AUTH_COGNITO_CLIENT_ID,
        'redirect_uri': auth_redirect_url
    })

    try:
        cognito_reply.raise_for_status()
    except requests.exceptions.HTTPError:
        return HttpResponse('Unauthorized', status=401)
    tokens: dict = cognito_reply.json()
    response = HttpResponseRedirect(app_redirect_url)
    for token_type in TOKEN_TYPES:
        request.session[token_type] = tokens[token_type]
    return response


@api_view(['GET'])
@authentication_classes([])
def logout(request):
    app_redirect_url: str = request.query_params.get('state', '')
    response = HttpResponseRedirect(app_redirect_url)
    request.session.flush()
    return response


def include_auth_urls():
    return include([
        path(r'login/', login),
        path(r'logout/', logout)
    ])