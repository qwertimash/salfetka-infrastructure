"""Bounded verified HTTPS, with local admin setup and CSRF-aware sessions."""
import http.cookiejar
import json
import ssl
import urllib.error
import urllib.request
import uuid

from .common import Failure, decode, require
from .releases import NoRedirect


class API:
    def __init__(self, origin, ca_file, browser_origin=None):
        self.origin, self.browser_origin = origin, browser_origin or origin
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        context.load_verify_locations(cafile=str(ca_file))
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(self.cookies), NoRedirect())
        self.csrf = None

    def call(self, path, body=None, *, key=None, revision=None):
        require(path.startswith('/api/v1/') or path in ('/healthz', '/readyz'), 'api_path_invalid')
        headers = {'Accept': 'application/json', 'Origin': self.browser_origin}
        if body is not None:
            headers['Content-Type'] = 'application/json'
            headers['Idempotency-Key'] = key or str(uuid.uuid4())
            if self.csrf: headers['X-CSRF-Token'] = self.csrf
        if revision is not None: headers['If-Match'] = '"' + str(revision) + '"'
        request = urllib.request.Request(self.origin + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            with self.opener.open(request, timeout=25) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                require(len(raw) <= 4 * 1024 * 1024, 'api_response_too_large')
                return decode(raw)
        except urllib.error.HTTPError as error:
            status = error.code; error.close()
            raise Failure('panel_api_rejected:' + str(status)) from None
        except (OSError, urllib.error.URLError): raise Failure('panel_api_unreachable') from None

    def login(self, username, password):
        value = self.call('/api/v1/auth/login', {'username': username, 'password': password})
        self.csrf = value['csrf_token']

    def logout(self):
        self.call('/api/v1/auth/logout', {})
        self.csrf = None; self.cookies.clear()
