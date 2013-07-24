# -*- coding: utf-8 -*-
import hashlib
import hmac
import requests

from urllib import urlencode
from urlparse import urlparse


TOKEN_ID_HEADER = 'X-Auth-Token'
TOKEN_SECRET_HEADER = 'X-Auth-Token-Secret'
SIGNATURE_HEADER = 'X-Auth-Signature'
CONSUMER_ID_HEADER = 'X-Auth-Key'


def utf8(value):
    """Returns utf-8 value for given input value.

    :param value: The value to encode.
    """
    if type(value) == unicode:
        value = value.encode('utf-8')
    return value


def compute_footprint(method, url, datas):
    """Computes a footprint for given request payload.

    :param method: The Http method.
    :param url: The ressource url.
    :param datas: The request datas.
    """
    parsed = urlparse(url)
    if len(parsed.query) > 0:
        url = "%s?%s" % (parsed.path, parsed.query)
    else:
        url = parsed.path
    if len(datas) > 0:
        datas = [(key, utf8(datas[key])) \
            for key in sorted(datas.keys())]
    return "%s&%s&%s" % (method.upper(), url, urlencode(datas))


def compute_signature(secret, method, url, datas={},
        digestmod=hashlib.sha256):
    """Computes an hmac signature from request payload.

    :param secret: The secret key.
    :param method: The Http method.
    :param url: The ressource url.
    :param datas: The request datas.
    :param digestmod: The digest algorhythm.
    """
    footprint = compute_footprint(method, url, datas)
    h = hmac.new(secret, digestmod=digestmod)
    h.update(footprint)
    return h.hexdigest()


class Client(object):
    TOKEN_ID_HEADER = TOKEN_ID_HEADER
    TOKEN_SECRET_HEADER = TOKEN_SECRET_HEADER
    SIGNATURE_HEADER = SIGNATURE_HEADER
    CONSUMER_ID_HEADER = CONSUMER_ID_HEADER

    def __init__(self, api_url, token_url, consumer_id=None,
            consumer_secret=None, token_id=None, token_secret=None,
            digestmod=hashlib.sha256):
        """Initializes a new XAuth client.

        :param api_url: The Api base url.
        :param token_url: The authentication token url.
        :param consumer_id: The consumer public_id.
        :param consumer_secret: The consumer secret.
        :param token_id: The authentication token public key.
        :param token_secret: The authentication token secret.
        """
        self.api_url = api_url
        self.token_url = token_url
        self.consumer_id = consumer_id
        self.consumer_secret = consumer_secret
        self.token_id = token_id
        self.token_secret = token_secret
        self.digestmod = digestmod

    def __getattr__(self, attr):
        """Act as a proxy for request.
        """
        if attr in ('get', 'post', 'put', 'patch', 'options', 'delete', ):
            return lambda url, **kwargs: self.request(attr, url, **kwargs)

    def authenticate(self, **kwargs):
        """Requests an authentication token.
        """
        r = self.get(self.token_url, **kwargs)
        self._handle_token(r.headers)
        return r

    def request(self, method, url, **kwargs):
        """Executes an Http request.

        :param method: The Http method.
        :param url: The ressource url.
        """
        req = requests.Request(method, "%s%s" % (self.api_url, url), **kwargs)
        r = req.prepare()

        r.headers[self.TOKEN_ID_HEADER] = self.token_id
        #  Consumer id
        if self.consumer_id is not None:
            r.headers[self.CONSUMER_ID_HEADER] = self.consumer_id
        #  Signature
        if self.consumer_secret is not None or self.token_secret is not None:
            secret = self.token_secret if self.token_secret is not None else ''
            if self.consumer_secret:
                secret += self.consumer_secret
            r.headers[self.SIGNATURE_HEADER] = compute_signature(str(secret), method,
                r.url, kwargs.get('data', {}), self.digestmod)

        s = requests.Session()
        return s.send(r, verify=False)

    def _handle_token(self, headers):
        """Sets authentication token values from headers.

        :param request: The request headers.
        """
        if self.TOKEN_ID_HEADER in headers and \
                self.TOKEN_SECRET_HEADER in headers:
            self.token_id = headers.get(self.TOKEN_ID_HEADER)
            self.token_secret = headers.get(self.TOKEN_SECRET_HEADER)
