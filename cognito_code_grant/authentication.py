from django.conf import settings
from django.db import transaction
from django.contrib.auth.models import User, Group

from rest_framework import authentication
from rest_framework import exceptions
from jose import jwt

from django.core.cache import cache

import requests


def _verify_token_and_decode(token: str, jwks: dict = None):
    # provided keys over cached keys over fetching new keys
    jwks = jwks or cache.get('jwks', None) or _fetch_cognito_keys()

    unverified_header = jwt.get_unverified_header(token)
    rsa_key = alg = None
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = key
            alg = key['alg']

    if not rsa_key:
        cache.delete('jwks')
        raise ValueError('No correct keys found to decode the auth payload!')

    return jwt.decode(
        token,
        rsa_key,
        audience=settings.AUTH_COGNITO_CLIENT_ID,
        algorithms=[alg],
        options={'verify_at_hash': False}) # TODO: verify this claim properly, see https://stackoverflow.com/questions/30356460/how-do-i-validate-an-access-token-using-the-at-hash-claim-of-an-id-token


def _fetch_cognito_keys():
    jwks = requests.get(settings.AUTH_COGNITO_JWKS_URL).json()
    cache.set('jwks', jwks, timeout=None)
    return jwks


def _refresh_tokens(refresh_token: str):
    return requests.post(settings.AUTH_COGNITO_CODE_GRANT_URL, data={
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': settings.AUTH_COGNITO_CLIENT_ID
        }).json()


class CognitoAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        access_token = request.session.get('access_token')
        id_token = request.session.get('id_token')
        refresh_token = request.session.get('refresh_token')

        if not access_token:
            # auth not attempted
            return None, None

        try:
            _verify_token_and_decode(access_token)
        except jwt.ExpiredSignatureError:
            new_tokens = _refresh_tokens(refresh_token)
            id_token = new_tokens.get('id_token')
            access_token = new_tokens.get('access_token')
            if not id_token:
                raise exceptions.AuthenticationFailed('Failed to fetch new tokens - invalid refresh token')
        except jwt.JWTError:
            raise exceptions.AuthenticationFailed('Invalid access token')

        decoded_id_token = _verify_token_and_decode(id_token)
        user = self.set_user(decoded_id_token)

        request.session['id_token'] = id_token
        request.session['access_token'] = access_token

        return (user, None)

    def set_user(self, decoded_id_token: dict):
        email = decoded_id_token['email']
        user_id = decoded_id_token['cognito:username']

        # transaction mostly required for distributed deployments
        with transaction.atomic():
            try:
                user = User.objects.select_for_update().get(username=user_id)
            except User.DoesNotExist:
                user = User.objects.create(username=user_id, email=email)
                user = User.objects.select_for_update().get(username=user_id)

            self.set_groups(user, decoded_id_token)

        return user

    def set_groups(self, user: User, decoded_id_token: dict):
        groups = decoded_id_token.get('cognito:groups', [])
        user_groups = user.groups.values_list('name', flat=True)
        missing_groups = set(groups) - set(user_groups)

        for missing_group in missing_groups:
            group, created = Group.objects.get_or_create(name=missing_group)
            group.user_set.add(user)