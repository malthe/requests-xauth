# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import mock
import sys
import requests
import requests_xauth
import os.path

try:
    from io import StringIO # python 3
except ImportError:
    from StringIO import StringIO # python 2
import unittest

if sys.version[0] == '3':
    bytes_type = bytes
else:
    bytes_type = str

def send(session, r, **kwargs):
    return r


class XAuthClientTest(unittest.TestCase):
    def make_one(self):
        return requests_xauth.Client(
            "https://i.b", "/auth",
            "my_id", "my_secret",
            "my_token_id", "my_token_secret"
        )

    @mock.patch('requests.Session.send', new=send)
    def test_request(self):
        client = self.make_one()

        r = client.request('get', '/path')
        self.assertEqual(
            dict(r.headers),
            {'X-Auth-Signature':
             'dd32cadd26f4902a73d26aeba07bd528b563061e0735853e74dd172160b7bf5a',
             'X-Auth-Key': u'my_id', 'X-Auth-Token': u'my_token_id'}
        )

    @mock.patch('requests.Session.send', new=send)
    def test_authenticate(self):
        client = self.make_one()

        r = client.authenticate()
        self.assertEqual(
            dict(r.headers),
            {'X-Auth-Signature':
             '53b1aecfba292868edc61b2a32b7e1fccf4efab5f65eb63f4fdbb25ce227f3b4',
             'X-Auth-Key': u'my_id', 'X-Auth-Token': u'my_token_id'}
        )
