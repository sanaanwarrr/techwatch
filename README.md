# Session Lab: local AiTM proof of concept

A working classroom demonstration inspired by the Rockstar-style flow in your notes. It uses a visibly labeled Gmail/Google-inspired mockup, one fixed fictional account, real local HTTP forwarding, a working time-based OTP, a server-issued session cookie, cross-profile replay, and server-side revocation. No external services, email delivery, or real accounts are involved.

## Run on macOS, Windows, or Linux

Requires Python 3.9 or newer. No pip packages are needed.

1. Extract this ZIP.
2. Open Terminal in the extracted `aitm_demo` folder.
3. Run:

```bash
python3 demo.py
```

On Windows, use `py demo.py` if `python3` is unavailable.

4. Open http://localhost:8765/console in your normal browser profile.
5. Open a separate Chrome profile (or a different browser) for the attacker. A fresh Incognito window also works if no previous Incognito session is open.

Use the exact hostnames shown below: `localhost` and `127.0.0.1` intentionally separate the cookies. All three servers bind only to IPv4 loopback. If localhost cannot connect, check local hostname resolution; do not substitute 127.0.0.1 for the application URL.

| Role | URL |
|---|---|
| Presenter console | http://localhost:8765/console |
| Victim email | http://127.0.0.1:8766/email |
| Attacker protected application | http://localhost:8765/vault |
| Attacker cookie import | http://localhost:8765/import |

Fictional email: `student@example.test`  
Fictional password: `DemoOnly!42`  
OTP: read the current six-digit code from the presenter console. Refresh the console to update it.

## Four-to-five-minute walkthrough

1. **Show the baseline.** In the attacker profile, open `/vault`. It returns HTTP 401 and “Login required.”
   Say: “This browser has no authenticated session.”
2. **Open the lure.** In the victim profile, open the simulated email, click Open shared document, then View document.
   Say: “The document-sharing chain leads the user into a login flow controlled by the relay.”
3. **Authenticate.** Enter the fictional password. Try an incorrect OTP once; it must fail. Refresh the presenter console and enter the displayed current OTP.
   Say: “The identity provider really checks both factors. The relay forwards those checks over local HTTP.”
4. **Show interception.** Refresh the presenter console. Point to Password accepted, OTP rejected, MFA accepted, and Intercepted Set-Cookie events. Copy the full captured token.
   Say: “The provider issued this session after MFA. The relay observed the actual response header.”
5. **Replay.** In the attacker profile, open `/import`, paste that token, and click Install test cookie. The private vault opens without a password or OTP. Compare its session fingerprint with the console.
   Say: “This lab helper installs the copied cookie. It does not authenticate or mint a new session.”
6. **Demonstrate the defense.** On the console, click Revoke all test sessions. Refresh the attacker vault and the victim document page. Both deny access. Importing the same old token again still fails.
   Say: “Revocation changes the server's session record, so every copy of this cookie stops working.”

## What is real, and what is simplified?

- Real: HTTP requests from the relay to the mock identity provider; password verification; HMAC-SHA1 TOTP with 30-second steps; one-use OTP steps; random session identifiers; interception of the provider's Set-Cookie header; host-only HttpOnly cookies; protected HTTP requests; session expiration and revocation.
- Simplified: three services share one Python process and in-memory state. The app checks the shared session registry instead of implementing a full OAuth/OIDC exchange. The relay only forwards three fixed local mock endpoints, not arbitrary websites or assets.
- The authenticator is displayed on a presenter console for convenience. In real MFA the second factor resides separately; this console is intentionally a teaching instrument.
- The import helper is a lab convenience standing in for installing a copied cookie. It accepts only tokens already issued by this running lab; importing never creates or renews a session. It intentionally lets you reinstall revoked/expired known tokens to demonstrate denial.
- Cookies use HTTP on loopback, so Secure is omitted. This is not production authentication code and does not demonstrate TLS interception. HttpOnly does not hide a Set-Cookie header from an intermediary terminating the authentication connection.
- Session lifetime is a chosen 10 minutes, not a claim about Microsoft settings. Expiration is enforced server-side even if reimport extends the browser cookie lifetime.
- OTP validation uses the current 30-second step only, without clock-skew allowance. The same step cannot be reused for another successful login. Challenges expire after 3 minutes and allow 5 attempts.
- No CAPTCHA bypass, bot evasion, external phishing infrastructure, Microsoft integration, or email sending is implemented.
- Console logs omit submitted passwords and OTPs. Captured tokens are intentionally visible and usable only inside this lab. State is discarded on restart. No telemetry or external network calls are made.

## Repeat, stop, and troubleshoot

- To repeat from a clean slate, press Ctrl+C in Terminal and rerun. All previous sessions become unknown. Existing browser cookies will fail until a new login/import succeeds.
- If a code expires while typing, refresh the console and enter the new code. After a successful login, wait until the next time step to authenticate again.
- If a challenge expires or reaches 5 attempts, go back to http://127.0.0.1:8766/login.
- If a port is already in use, stop the earlier demo process before restarting. Ports 8765–8767 are fixed intentionally.
- The console does not auto-refresh; use its Refresh console / OTP link to get current codes, captures, and events.
- If both browser windows are logged in before importing, you may have used two windows of the same profile. Use a different browser or a truly separate profile.
- All services are local development servers. Keep them on loopback; no public hosting is needed for the presentation.

## Verification

With the demo stopped, run:

```bash
python3 -m unittest -v test_demo.py
```

The integration test starts the actual servers and checks denial before login, rejection of a wrong password and OTP, successful relay authentication, cookie isolation between hosts/profiles, replay access, used-challenge rejection, revocation of both copies, expiration, unknown-token rejection, origin/form protection, Host validation, and denial of unauthenticated identity-provider API requests.

## Files

- `demo.py`: complete runnable application, annotated at key boundaries.
- `test_demo.py`: actual-HTTP end-to-end regression test.
- `README.md`: setup, demonstration script, architecture limits, and troubleshooting.

## Updated visual design

The email screen now uses a Gmail-inspired sidebar, message toolbar, sender row, and document-sharing card. The login and OTP screens use Google-inspired typography, colors, rounded panels, and a two-column layout. The document viewer and presenter tools use a coordinated light theme. Every screen includes a visible Training demo label.

`views.py` contains all presentation templates and CSS. Keep it beside `demo.py`. No external fonts, images, scripts, or Google endpoints are loaded. Sidebar/search decorations are labeled as visual mockups. The actionable document, sign-in, OTP, replay, and revocation flow remains functional.

## Form-origin fix

The response now uses `Referrer-Policy: same-origin`. The old `no-referrer` setting could make browser form POSTs send `Origin: null`, which the local origin check rejected before password or OTP validation. Origin and form-token checks remain enabled. After updating, stop the old process, start the updated demo, and reopen `/login` directly; do not resubmit an old browser form. Stale forms now display a reload link.
