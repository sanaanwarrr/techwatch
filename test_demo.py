"""End-to-end checks over actual loopback HTTP, using isolated cookie jars."""
import http.cookiejar
import re
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import demo

class FlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.servers = demo.start()
    @classmethod
    def tearDownClass(cls):
        for s in cls.servers: s.shutdown(); s.server_close()

    def browser(self):
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))

    def request(self, client, url, data=None, headers=None):
        headers = dict(headers or {})
        if data is not None:
            headers.setdefault('Origin', urllib.parse.urlsplit(url).scheme + '://' + urllib.parse.urlsplit(url).netloc)
            data = urllib.parse.urlencode(data).encode()
        try: response = client.open(urllib.request.Request(url,data=data,headers=headers or {}),timeout=3)
        except urllib.error.HTTPError as exc: response = exc
        with response: return response.status,response.read().decode()

    def test_form_policy(self):
        client = self.browser()
        with client.open(demo.RELAY+'/login') as response:
            self.assertEqual(response.headers['Referrer-Policy'], 'same-origin')
            body = response.read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
        status, body = self.request(client, demo.RELAY+'/password',
            {'csrf':csrf, 'username':demo.USER, 'password':demo.PASSWORD},
            {'Origin':demo.RELAY})
        self.assertEqual(status, 200)
        self.assertIn('2-Step Verification', body)
        self.assertIn('name="otp"', body)
        self.assertEqual(self.request(client, demo.RELAY+'/password',
            {'csrf':csrf}, {'Origin':'null'})[0], 403)
        status, body = self.request(client, demo.RELAY+'/password', {'csrf':'old-run'})
        self.assertEqual(status,403)
        self.assertIn('earlier run',body)

    def test_end_to_end(self):
        victim, attacker = self.browser(), self.browser()
        self.assertEqual(self.request(attacker,demo.APP+'/vault')[0],401)
        for path in ['/email','/document','/login']:
            self.assertEqual(self.request(victim,demo.RELAY+path)[0],200)
        status,_=self.request(victim,demo.RELAY+'/password',{'csrf':demo.KEY,'username':demo.USER,'password':'wrong'})
        self.assertEqual(status,401); self.assertFalse(demo.SESSIONS)
        status,body=self.request(victim,demo.RELAY+'/password',{'csrf':demo.KEY,'username':demo.USER,'password':demo.PASSWORD})
        self.assertEqual(status,200)
        challenge=re.search(r'name="challenge" value="([^"]+)"',body).group(1)
        status,_=self.request(victim,demo.RELAY+'/otp',{'csrf':demo.KEY,'challenge':challenge,'otp':'invalid'})
        self.assertEqual(status,401); self.assertFalse(demo.SESSIONS)
        # Freeze the code clock during this request so a 30-second boundary cannot flake the test.
        from unittest.mock import patch
        now=time.time()
        with patch.object(demo.time,'time',return_value=now):
            status,body=self.request(victim,demo.RELAY+'/otp',{'csrf':demo.KEY,'challenge':challenge,'otp':demo.otp_at(int(now//30))})
        self.assertEqual(status,200); self.assertIn('MFA completed',body)
        token=demo.CAPTURED[-1]
        self.assertTrue(demo.valid(token))
        # Relay cookie must not automatically authenticate localhost, even in victim profile.
        self.assertEqual(self.request(victim,demo.APP+'/vault')[0],401)
        self.assertEqual(self.request(attacker,demo.APP+'/vault')[0],401)
        status,body=self.request(attacker,demo.APP+'/import',{'csrf':demo.KEY,'token':token})
        self.assertEqual(status,200); self.assertIn('Project Aurora',body)
        self.assertIn(demo.fingerprint(token),body)
        # Used challenge cannot issue a second session.
        self.assertEqual(self.request(victim,demo.RELAY+'/otp',{'csrf':demo.KEY,'challenge':challenge,'otp':demo.otp_at(int(now//30))})[0],401)
        self.assertEqual(len(demo.SESSIONS),1)
        self.assertEqual(self.request(attacker,demo.APP+'/revoke',{'csrf':'bad'})[0],403)
        self.assertEqual(self.request(attacker,demo.APP+'/revoke',{'csrf':demo.KEY}, {'Origin':'https://example.com'})[0],403)
        self.assertEqual(self.request(attacker,demo.APP+'/revoke',{'csrf':demo.KEY})[0],200)
        self.assertEqual(self.request(attacker,demo.APP+'/vault')[0],401)
        self.assertEqual(self.request(victim,demo.RELAY+'/vault')[0],401)
        self.assertEqual(self.request(attacker,demo.APP+'/import',{'csrf':demo.KEY,'token':token})[0],401)
        demo.SESSIONS[token]={'expires':time.time()-1,'revoked':False}
        self.assertEqual(self.request(attacker,demo.APP+'/vault')[0],401)
        self.assertEqual(self.request(attacker,demo.APP+'/import',{'csrf':demo.KEY,'token':'made-up'})[0],400)
        self.assertEqual(self.request(attacker,demo.APP+'/',headers={'Host':'evil.example'})[0],403)
        self.assertEqual(self.request(attacker,demo.IDP+'/password',{'username':demo.USER,'password':demo.PASSWORD})[0],403)

if __name__ == '__main__': unittest.main(verbosity=2)
