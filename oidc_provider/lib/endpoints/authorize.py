from datetime import timedelta
from hashlib import (
    md5,
    sha256,
)
import logging
try:
    from urllib import urlencode
    from urlparse import urlsplit, parse_qs, urlunsplit
except ImportError:
    from urllib.parse import urlsplit, parse_qs, urlunsplit, urlencode, quote
from uuid import uuid4

from django.utils import timezone
from marshmallow import Schema, fields, validate, EXCLUDE

from oidc_provider.lib.claims import StandardScopeClaims

from oidc_provider.lib.errors import (
    AuthorizeError,
    ClientIdError,
    RedirectUriError,
    _errors
)
from oidc_provider.lib.utils.token import (
    create_code,
    create_id_token,
    create_token,
    encode_id_token,
)
from oidc_provider.models import (
    Client,
    UserConsent,
)
from oidc_provider import settings
from oidc_provider.lib.utils.common import get_browser_state_or_default

logger = logging.getLogger(__name__)

_allowed_prompt_params = {'none', 'login', 'consent', 'select_account'}


class AuthorizeEndpoint(object):
    client_class = Client

    def __init__(self, request):
        self.request = request
        self.params = {}

    def validate_params(self):
        query_dict = (self.request.POST if self.request.method == 'POST'
                      else self.request.GET)

        self.params = AuthorizeSchema().load(query_dict)

        # Determine if it's an OpenID Authentication request (or OAuth2).
        self.is_authentication = 'openid' in self.params['scope']

        try:
            self.client = self.client_class.objects.get(client_id=self.params['client_id'])
        except Client.DoesNotExist:
            logger.debug('[Authorize] Invalid client identifier: %s', self.params['client_id'])
            raise ClientIdError()


    def create_response_uri(self):
        uri = urlsplit(self.params['redirect_uri'])
        query_params = parse_qs(uri.query)
        query_fragment = {}

        try:
            if self.grant_type in ['authorization_code', 'hybrid']:
                code = create_code(
                    user=self.request.user,
                    client=self.client,
                    scope=self.params['scope'],
                    nonce=self.params['nonce'],
                    is_authentication=self.is_authentication,
                    code_challenge=self.params['code_challenge'],
                    code_challenge_method=self.params['code_challenge_method'])
                code.save()

            if self.grant_type == 'authorization_code':
                query_params['code'] = code.code
                query_params['state'] = self.params['state'] if self.params['state'] else ''
            elif self.grant_type in ['implicit', 'hybrid']:
                token = create_token(
                    user=self.request.user,
                    client=self.client,
                    scope=self.params['scope'])

                # Check if response_type must include access_token in the response.
                if (self.params['response_type'] in
                        ['id_token token', 'token', 'code token', 'code id_token token']):
                    query_fragment['access_token'] = token.access_token

                # We don't need id_token if it's an OAuth2 request.
                if self.is_authentication:
                    kwargs = {
                        'token': token,
                        'user': self.request.user,
                        'aud': self.client.client_id,
                        'nonce': self.params['nonce'],
                        'request': self.request,
                        'scope': self.params['scope'],
                    }
                    # Include at_hash when access_token is being returned.
                    if 'access_token' in query_fragment:
                        kwargs['at_hash'] = token.at_hash
                    id_token_dic = create_id_token(**kwargs)

                    # Check if response_type must include id_token in the response.
                    if self.params['response_type'] in [
                            'id_token', 'id_token token', 'code id_token', 'code id_token token']:
                        query_fragment['id_token'] = encode_id_token(id_token_dic, self.client)
                else:
                    id_token_dic = {}

                # Store the token.
                token.id_token = id_token_dic
                token.save()

                # Code parameter must be present if it's Hybrid Flow.
                if self.grant_type == 'hybrid':
                    query_fragment['code'] = code.code

                query_fragment['token_type'] = 'bearer'

                query_fragment['expires_in'] = settings.get('OIDC_TOKEN_EXPIRE')

                query_fragment['state'] = self.params['state'] if self.params['state'] else ''

            if settings.get('OIDC_SESSION_MANAGEMENT_ENABLE'):
                # Generate client origin URI from the redirect_uri param.
                redirect_uri_parsed = urlsplit(self.params['redirect_uri'])
                client_origin = '{0}://{1}'.format(
                    redirect_uri_parsed.scheme, redirect_uri_parsed.netloc)

                # Create random salt.
                salt = md5(uuid4().hex.encode()).hexdigest()

                # The generation of suitable Session State values is based
                # on a salted cryptographic hash of Client ID, origin URL,
                # and OP browser state.
                session_state = '{client_id} {origin} {browser_state} {salt}'.format(
                    client_id=self.client.client_id,
                    origin=client_origin,
                    browser_state=get_browser_state_or_default(self.request),
                    salt=salt)
                session_state = sha256(session_state.encode('utf-8')).hexdigest()
                session_state += '.' + salt
                if self.grant_type == 'authorization_code':
                    query_params['session_state'] = session_state
                elif self.grant_type in ['implicit', 'hybrid']:
                    query_fragment['session_state'] = session_state

        except Exception as error:
            logger.exception('[Authorize] Error when trying to create response uri: %s', error)
            raise AuthorizeError(self.params['redirect_uri'], 'server_error', self.grant_type)

        uri = uri._replace(
            query=urlencode(query_params, doseq=True),
            fragment=uri.fragment + urlencode(query_fragment, doseq=True))

        return urlunsplit(uri)

    def set_client_user_consent(self):
        """
        Save the user consent given to a specific client.

        Return None.
        """
        date_given = timezone.now()
        expires_at = date_given + timedelta(
            days=settings.get('OIDC_SKIP_CONSENT_EXPIRE'))

        uc, created = UserConsent.objects.get_or_create(
            user=self.request.user,
            client=self.client,
            defaults={
                'expires_at': expires_at,
                'date_given': date_given,
            }
        )
        uc.scope = self.params['scope']

        # Rewrite expires_at and date_given if object already exists.
        if not created:
            uc.expires_at = expires_at
            uc.date_given = date_given

        uc.save()

    def client_has_user_consent(self):
        """
        Check if already exists user consent for some client.

        Return bool.
        """
        try:
            uc = UserConsent.objects.get(user=self.request.user, client=self.client)
            if (set(self.params['scope']).issubset(uc.scope)) and not (uc.has_expired()):
                return True
        except UserConsent.DoesNotExist:
            pass

        return False

    def get_scopes_information(self):
        """
        Return a list with the description of all the scopes requested.
        """
        scopes = StandardScopeClaims.get_scopes_info(self.params['scope'])
        if settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
            scopes_extra = settings.get(
                'OIDC_EXTRA_SCOPE_CLAIMS', import_str=True).get_scopes_info(self.params['scope'])
            for index_extra, scope_extra in enumerate(scopes_extra):
                for index, scope in enumerate(scopes[:]):
                    if scope_extra['scope'] == scope['scope']:
                        del scopes[index]
        else:
            scopes_extra = []

        return scopes + scopes_extra


class StrList(fields.List):
    """
    Extends List to support serializing and deserializing delimeter separated strings.
    """

    def __init__(self, cls_or_instance, separator=",", **kwargs):
        self.separator = separator
        super().__init__(cls_or_instance, **kwargs)

    def _serialize(self, value, attr, obj, **kwargs):
        return self.separator.join(super()._serialize(value, attr, obj, **kwargs))

    def _deserialize(self, value, attr, data, **kwargs):
        return super()._deserialize(value.split(self.separator), attr, data, **kwargs)


class ValidationError(Exception):
    def __init__(self, error, redirectable, state, redirect_uri, response_type):
        self.error = error
        self.redirectable = redirectable
        self.description = quote(_errors.get(self.error, ''))
        self.state = state
        self.redirect_uri = redirect_uri

        if response_type in ['code']:
            self.grant_type = 'authorization_code'
        elif response_type in ['id_token', 'id_token token', 'token']:
            self.grant_type = 'implicit'
        elif response_type in [
                'code token', 'code id_token', 'code id_token token']:
            self.grant_type = 'hybrid'
        else:
            self.grant_type = None

    def uri(self):
        # http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthError
        hash_or_question = '#' if self.grant_type == 'implicit' else '?'

        uri = '{0}{1}error={2}&error_description={3}'.format(
            self.redirect_uri,
            hash_or_question,
            self.error,
            self.description)

        # Add state if present.
        return uri + '&state={0}'.format(self.state or '')

    def render_context(self):
        return {'error': self.error, 'description': self.description}


class AuthorizeSchema(Schema):
    class Meta:
        unknown = EXCLUDE

    # Required

    scope = StrList(fields.Str(), required=True, separator=' ')
    response_type = fields.Str(
        required=True,
    )
    client_id = fields.Str(required=True)
    redirect_uri = fields.URL(relative=False, required=True)
    # Recommended

    state = fields.Str(required=False)

    # Optional

    # default for code=query, default for token=fragment
    nonce = fields.Str()
    prompt = StrList(
        fields.Str(
            validate=validate.OneOf(_allowed_prompt_params)
        ),
        missing=(),
        separator=" "
    )

    # TODO: timestamp field
    max_age = fields.Str()

    # PKCE
    # TODO: Should be base64
    code_challenge = fields.Str()
    code_challenge_method = fields.Str(
        validate=validate.OneOf(['S256', 'plain']),
    )

    # There are more values supported in the authorize request, but they're optional and
    # not currently supported by django-oidc-provider

    def handle_error(self, error, data, *, many, **kwargs):
        print(error)
        print(data)
        raise ValidationError(
            error=list(error.messages.keys())[0]
            if isinstance(error.messages, dict) and len(error.messages.keys()) > 0
            else 'invalid_request',
            # Whether we passed enough information to be able to redirect the error to the RP
            # Otherwise we have to render the error to the user.
            redirectable={'client_id', 'redirect_uri'}.issubset(error.valid_data.keys()),
            state=data.get('state'),
            redirect_uri=data.get('redirect_uri'),
            response_type=data.get('response_type')
        ) from error
