#!/usr/bin/env python3
"""Loopback-only classroom AiTM lab. Python 3.9+, no dependencies."""
import hashlib
import hmac
import html
import http.cookies
import json
import secrets
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP = 'http://localhost:8765'
RELAY = 'http://127.0.0.1:8766'
IDP = 'http://127.0.0.1:8767'
USER = 'student@example.test'
PASSWORD = 'DemoOnly!42'
KEY = secrets.token_hex(24)
OTP_SECRET = secrets.token_bytes(20)
COOKIE = 'classroom_session'
TTL = 600
LOCK = threading.RLock()
SESSIONS, CHALLENGES, EVENTS = {}, {}, []
CAPTURED = []
LAST_OTP_STEP = -1

def otp_at(step):
    digest = hmac.new(OTP_SECRET, struct.pack('>Q', step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000).zfill(6)

def fingerprint(token):
    return hashlib.sha256(token.encode()).hexdigest()[:12]

def event(actor, message):
    with LOCK:
        EVENTS.append((time.strftime('%H:%M:%S'), actor, message))
        del EVENTS[:-100]

def valid(token):
    with LOCK:
        record = SESSIONS.get(token)
        return bool(record and not record['revoked'] and record['expires'] > time.time())

def e(value):
    return html.escape(str(value), quote=True)

def form(action, content, label):
    return f'<form method="post" action="{e(action)}"><input type="hidden" name="csrf" value="{KEY}">{content}<button>{e(label)}</button></form>'

# Presentation lives separately; authentication and relay behavior are unchanged.
from views import render as page

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    @property
    def role(self):
        return self.server.role

    def send(self, body, status=200, headers=None, content_type='text/html; charset=utf-8'):
        raw = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        # Preserve Origin on same-origin form POSTs so origin validation works.
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, path, cookie=None):
        headers = {'Location': path}
        if cookie:
            headers['Set-Cookie'] = cookie
        self.send('', 303, headers)

    def token(self):
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get('Cookie', ''))
            return jar[COOKIE].value if COOKIE in jar else ''
        except http.cookies.CookieError:
            return ''

    def guard(self):
        expected = {'app': 'localhost:8765', 'relay': '127.0.0.1:8766', 'idp': '127.0.0.1:8767'}[self.role]
        if self.headers.get('Host') != expected or self.client_address[0] != '127.0.0.1':
            self.send('Use the exact loopback URL printed by demo.py.', 403)
            return False
        return True

    def do_GET(self):
        if not self.guard(): return
        path = urllib.parse.urlsplit(self.path).path
        if self.role == 'idp':
            self.send('Mock identity provider: fixed internal API only.', 404)
            return
        if self.role == 'app':
            if path == '/':
                self.send(page('Session theft, made visible', f'<div class="card"><p>Three local services. Two browser profiles. One session reused.</p><a class="button" href="/console">Presenter console</a><a class="button" href="{RELAY}/email">Victim: open email</a><a class="button" href="/vault">Protected application</a><a href="/import">Attacker: import test cookie</a></div>'))
            elif path == '/console':
                with LOCK:
                    rows = ''.join(f'<tr><td>{e(t)}</td><td>{e(a)}</td><td>{e(m)}</td></tr>' for t,a,m in reversed(EVENTS))
                    captures = ''.join(f'<div class="card"><small>Intercepted Set-Cookie • fingerprint {fingerprint(t)} • {"ACTIVE" if valid(t) else "INVALID"}</small><p><code>{e(t)}</code></p></div>' for t in reversed(CAPTURED)) or '<p>No session intercepted yet.</p>'
                step = int(time.time() // 30)
                body = f'<p><a href="/console">Refresh console / OTP</a> · <a href="{RELAY}/email">Open simulated email</a></p><div class="grid"><section class="card"><h2>Fictional account</h2><code>{USER}</code><p><code>{PASSWORD}</code></p><small>Only these credentials are accepted.</small></section><section class="card"><h2>Lab authenticator</h2><div class="otp">{otp_at(step)}</div><p>Valid for {30-int(time.time())%30} more seconds at page load. Refresh for a new code.</p><small>Each time step can be used once. After a successful run, wait for the next code.</small></section></div><h2>Captured test session cookies</h2>{captures}<p>Copy a token into <code>{APP}/import</code> in your separate attacker profile. The import page only installs a cookie; it cannot create a session.</p>{form("/revoke", "", "Revoke all test sessions")}<h2>Live evidence (refresh to update)</h2><table><tr><th>Time</th><th>Component</th><th>Event</th></tr>{rows}</table>'
                self.send(page('Presenter console', body))
            elif path == '/import':
                self.send(page('Import intercepted test cookie', '<p>This lab-only helper represents copying a stolen cookie into another browser. Paste the exact token from the presenter console.</p>'+form('/import','<label>Test session token<input name="token" required maxlength="128" autocomplete="off"></label>','Install test cookie')))
            elif path == '/vault':
                token = self.token()
                if not valid(token):
                    event('Application', 'Protected request denied: missing, expired, or revoked session.')
                    self.send(page('Login required', f'<div class="card"><p class="error">Access denied. No valid session.</p><a href="{RELAY}/email">Begin victim flow</a> · <a href="/import">Import test cookie</a></div>'), 401)
                else:
                    event('Application', 'Protected request accepted; session '+fingerprint(token))
                    self.send(page('Private document vault', f'<div class="card"><p class="ok">Authenticated as {USER}</p><p>Session fingerprint: <code>{fingerprint(token)}</code></p><h2>Project Aurora — internal budget</h2><p>Fictional allocation: $12,500<br>Owner: Jordan Example<br>Status: Confidential classroom sample</p><p>This information is served only after a server-side session check.</p><a href="/vault">Refresh protected document</a></div>'))
            else: self.send('Not found', 404)
            return
        if path in ('/', '/email'):
            self.send(page('A document was shared with you', f'<div class="card"><small>SIMULATED INBOX · NO EMAIL IS SENT</small><h2>Jordan Example shared “Project Aurora”</h2><p>Hi Student, please review the updated project budget before our meeting.</p><a class="button" href="/document">Open shared document</a></div>'))
        elif path == '/document':
            self.send(page('Project Aurora.pdf', '<div class="card"><small>SIMULATED DOCUMENT VIEWER</small><h2>Preview requires sign-in</h2><p>One page · Internal planning document</p><a class="button" href="/login">View document</a></div>'))
        elif path == '/login': self.login_page()
        elif path == '/vault':
            token = self.token()
            status, payload, _ = self.backend('/validate', {'token':token})
            if status == 200:
                self.send(page('Your document is ready', f'<div class="card"><p class="ok">MFA completed through the relay.</p><p>Fictional allocation: $12,500</p><p>Session fingerprint: <code>{fingerprint(token)}</code></p><a href="/vault">Refresh session check</a></div>'))
            else: self.send(page('Login required', '<p>Session expired or revoked.</p><a href="/login">Sign in again</a>'),401)
        else: self.send('Not found',404)

    def login_page(self, message='', status=200):
        fields = '<label>Email<input name="username" value="student@example.test" required autocomplete="off"></label><label>Password<input name="password" type="password" required autocomplete="off"></label>'
        self.send(page('Sign in to Example Workspace', f'<p class="error">{e(message)}</p><div class="card">'+form('/password',fields,'Continue')+'</div>'),status)

    def otp_page(self, challenge, message='', status=200):
        fields = f'<input type="hidden" name="challenge" value="{e(challenge)}"><label>Six-digit authenticator code<input name="otp" required pattern="[0-9]{{6}}" inputmode="numeric" autocomplete="off"></label>'
        self.send(page('Verify your identity', f'<p class="error">{e(message)}</p><div class="card"><p>Use the lab authenticator on the presenter console.</p>'+form('/otp', fields,'Verify and open document')+'</div>'),status)

    def backend(self, path, values):
        # Fixed endpoints, no user-supplied destinations, no external proxy support.
        assert path in ('/password','/otp','/validate')
        event('Relay', 'Forwarding POST '+path+' to local mock identity provider (values omitted).')
        req = urllib.request.Request(IDP+path, data=urllib.parse.urlencode(values).encode(), headers={'X-Lab-Key':KEY}, method='POST')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(req, timeout=3)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            return response.status, json.loads(response.read()), response.headers.get('Set-Cookie')

    def do_POST(self):
        if not self.guard(): return
        try:
            length = int(self.headers.get('Content-Length','0'))
            if not 0 <= length <= 4096: raise ValueError()
            values = {k:v[0] for k,v in urllib.parse.parse_qs(self.rfile.read(length).decode(), max_num_fields=12).items()}
        except (ValueError, UnicodeError):
            self.send('Invalid request',400); return
        path = urllib.parse.urlsplit(self.path).path
        if self.role == 'idp':
            if not hmac.compare_digest(self.headers.get('X-Lab-Key',''), KEY):
                self.send('{}',403,content_type='application/json'); return
            self.identity(path, values); return
        expected_origin = APP if self.role == 'app' else RELAY
        if not hmac.compare_digest(values.get('csrf',''), KEY):
            self.send(page('Please reload the demo', '<p>This form belongs to an earlier run of the demo. Open a fresh page and try again.</p><a href="/login">Return to sign in</a>' if self.role == 'relay' else '<p>This form belongs to an earlier run. Reload the presenter console.</p><a href="/console">Presenter console</a>'),403); return
        if self.headers.get('Origin',expected_origin) != expected_origin:
            self.send(page('Please reopen the sign-in page', '<p>The browser did not send the expected local origin. Reopen the page using the link below, rather than resubmitting the old form.</p><a href="/login">Reload sign in</a>' if self.role == 'relay' else '<p>Reload the presenter console before submitting again.</p><a href="/console">Presenter console</a>'),403); return
        if self.role == 'app':
            if path == '/import':
                token = values.get('token','').strip()
                with LOCK: known = token in SESSIONS
                if not known:
                    self.send(page('Unknown test token','<p>Copy an issued token from the presenter console.</p><a href="/import">Try again</a>'),400); return
                event('Import helper','Installed copied cookie '+fingerprint(token)+'; no authentication performed.')
                self.redirect('/vault',cookie_header(token)); return
            if path == '/revoke':
                with LOCK:
                    for record in SESSIONS.values(): record['revoked'] = True
                event('Defense','All server-side sessions revoked. Both browser copies now fail validation.')
                self.redirect('/console'); return
        if self.role == 'relay' and path in ('/password','/otp'):
            try: status, result, cookie = self.backend(path, {k:v for k,v in values.items() if k != 'csrf'})
            except (urllib.error.URLError, TimeoutError):
                self.send(page('Provider unavailable','<p>Restart the demo and retry.</p>'),502); return
            if path == '/password':
                if status != 200: self.login_page(result['error'],status)
                else: self.otp_page(result['challenge'])
            elif status != 200: self.otp_page(values.get('challenge',''),result['error'],status)
            else:
                jar = http.cookies.SimpleCookie(); jar.load(cookie)
                token = jar[COOKIE].value
                with LOCK: CAPTURED.append(token)
                event('Relay','Intercepted real mock-provider Set-Cookie; session '+fingerprint(token))
                self.redirect('/vault',cookie)
            return
        self.send('Not found',404)

    def identity(self, path, values):
        global LAST_OTP_STEP
        status, result, headers = 200, {}, {}
        with LOCK:
            if path == '/password':
                if values.get('username') != USER or values.get('password') != PASSWORD:
                    status,result = 401,{'error':'Use only the supplied fictional credentials.'}
                    event('Identity provider','Password rejected; no session issued.')
                else:
                    challenge = secrets.token_urlsafe(24)
                    CHALLENGES[challenge] = {'expires':time.time()+180,'attempts':0}
                    result = {'challenge':challenge}
                    event('Identity provider','Password accepted. MFA challenge issued; no session yet.')
            elif path == '/otp':
                challenge = values.get('challenge','')
                record = CHALLENGES.get(challenge)
                step = int(time.time()//30)
                if not record or record['expires'] < time.time() or record['attempts'] >= 5:
                    status,result = 401,{'error':'Challenge expired or exhausted. Restart from Sign in.'}
                else:
                    record['attempts'] += 1
                    if step <= LAST_OTP_STEP or not hmac.compare_digest(values.get('otp',''),otp_at(step)):
                        status,result = 401,{'error':'Incorrect, expired, or already-used OTP. Refresh the console for a fresh code.'}
                        event('Identity provider','OTP rejected; no session issued.')
                    else:
                        LAST_OTP_STEP = step
                        del CHALLENGES[challenge]
                        token = secrets.token_urlsafe(32)
                        SESSIONS[token] = {'expires':time.time()+TTL,'revoked':False}
                        headers['Set-Cookie'] = cookie_header(token)
                        result = {'authenticated':True}
                        event('Identity provider','MFA accepted; issued session '+fingerprint(token)+' (10-minute lab lifetime).')
            elif path == '/validate':
                good = valid(values.get('token',''))
                status,result = (200 if good else 401),{'valid':good}
            else: status,result = 404,{'error':'Unknown endpoint'}
        self.send(json.dumps(result),status,headers,'application/json')

def cookie_header(token):
    # HTTP loopback lab: Secure intentionally omitted; never use this as production auth.
    return f'{COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={TTL}'

def start():
    servers = []
    try:
        for role,port in [('app',8765),('relay',8766),('idp',8767)]:
            server = ThreadingHTTPServer(('127.0.0.1',port),Handler)
            server.role = role
            servers.append(server)
        for server in servers:
            threading.Thread(target=server.serve_forever,daemon=True).start()
    except OSError:
        for server in servers: server.server_close()
        raise
    return servers

if __name__ == '__main__':
    servers = start()
    print(f'\nSession Lab running.\nPresenter: {APP}/console\nVictim: {RELAY}/email\nAttacker: {APP}/vault\nImport helper: {APP}/import\n\nCtrl+C stops all services. Restart clears all lab state.\n',flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown(); server.server_close()
