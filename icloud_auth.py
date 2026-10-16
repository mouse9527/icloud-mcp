#!/usr/bin/env python3
"""icloud-auth: one-time link login for the iCloud MCP (no password at rest).

Two listeners in one process:
  :8000  login page, reachable from the internet via ingress. 404 unless a
         pending one-time token matches.
  :8001  MCP (Streamable HTTP, stateless JSON) for Open WebUI:
         icloud_login_start / icloud_login_status.

The login page is one static HTML page; state changes are pushed over
server-sent events (/<user>/<token>/events, same token + cookie checks). A
password POST returns at once and the Apple conversation runs in a worker
thread, so the code form appears as soon as Apple asks for a code.

The password only exists in the POST handler's locals, the worker thread's
locals and inside the PyiCloudService object until SRP completes. Nothing logs it: Python
logging is disabled, access logs mask the token, exceptions are reduced to
their class name. The session produced by pyicloud is written to a private
staging dir, then renamed to <SESSION_ROOT>/incoming with READY created last;
reminders_worker_reload.py adopts it before its next request.
"""
import hmac
import html
import json
import logging
import os
from pathlib import Path
import secrets
import shutil
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN_TTL = 300          # link must be used within 5 minutes
FLOW_TTL = 900           # 2FA / device approval must finish within 15 minutes
MAX_CODE_ATTEMPTS = 3
MAX_BODY = 4096
SSE_HEARTBEAT = 15       # seconds; keeps ingress / proxies from closing an idle stream

# Login states pushed to the page. Only these names and fixed Chinese copy ever
# leave the server: no Apple ID, token or upstream error text.
#   link       -> waiting for the password
#   signing_in -> password received, talking to Apple (SRP)
#   code       -> Apple asked for a 6-digit code (shown as soon as SRP says so)
#   verifying  -> code received; submitted once the 2FA prompt is ready
#   approve    -> waiting for "allow access to iCloud data" on a device (PCS)
#   done / failed (terminal; the token is gone afterwards)
FAIL_COPY = {
    "password": "Apple ID 或密码不对。",
    "code": "验证码连续 3 次不对。",
    "timeout": "等待 Apple 响应超时（验证码或设备批准没有及时完成）。",
    "unsupported": "这个账号的验证方式不受支持（安全密钥或旧式两步验证）。",
    "apple": "Apple 拒绝了这次登录，或暂时无法完成。",
}


def log(event, **fields):
    """The only log sink. Never pass secrets here."""
    record = {"ts": int(time.time()), "event": event, **fields}
    print(json.dumps(record, ensure_ascii=False), file=sys.stderr, flush=True)


def safe_excepthook(args):
    log("thread_error", error=type(args.exc_value).__name__)


class Unsupported(Exception):
    pass


class WrongPassword(Exception):
    pass


def classify(error):
    """Map an exception to a FAIL_COPY key without looking at its text."""
    if isinstance(error, Unsupported):
        return "unsupported"
    if isinstance(error, WrongPassword):
        return "password"
    if isinstance(error, TimeoutError):
        return "timeout"
    name = type(error).__name__
    if name == "PyiCloudFailedLoginException":
        return "password"
    if "Timeout" in name:
        return "timeout"
    return "apple"


class Login:
    """One pending login. Mutated by its worker thread; watched by SSE streams."""

    def __init__(self, token, now):
        self.token = token
        self.cookie = secrets.token_urlsafe(24)
        self.created = now
        self.state = "link"
        self.message = ""
        self.reason = None
        self.api = None
        self.staging = None
        self.code_attempts = 0
        self.pending_code = None
        self.lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        self.version = 0

    def expired(self, now):
        if self.state == "link":
            return now - self.created > TOKEN_TTL
        return now - self.created > FLOW_TTL

    def set(self, state, message=""):
        """Caller holds self.lock."""
        self.state, self.message = state, message
        self.version += 1
        self.changed.notify_all()

    def snapshot(self):
        """Caller holds self.lock. The only data an SSE event carries."""
        return {"state": self.state, "message": self.message}


class PyiCloudBackend:
    """Thin seam over pyicloud so tests can run without an Apple account.

    start() runs in the login worker thread. pyicloud requests the 2FA prompt
    from inside authenticate() and then blocks until Apple answers on the
    trusted-device bridge (up to 30 s), although the iPhone already shows the
    code. We swap request_2fa_code on the *instance* so the page can switch to
    the code form the moment pyicloud decides a code is needed. This depends on
    pyicloud calling self.request_2fa_code() from _srp_authentication (pinned
    86c4bc90, base.py:695); re-check when upgrading pyicloud.
    """

    def __init__(self, apple_id):
        self.apple_id = apple_id

    def start(self, password, staging, on_need_code):
        from pyicloud import PyiCloudService
        api = PyiCloudService(self.apple_id, password=password, cookie_directory=str(staging),
                              with_family=False, accept_terms=False, authenticate=False)
        original = api.request_2fa_code

        def request_2fa_code():
            if not getattr(api, "security_key_names", None):
                on_need_code()
            return original()

        api.request_2fa_code = request_2fa_code
        try:
            api.authenticate()
        finally:
            # SRP is done; later steps (2FA, trust, PCS) only use session tokens.
            api._password_raw = None
        if api.requires_2sa and not api.requires_2fa:
            raise Unsupported("legacy two-step verification")
        if api.requires_2fa and getattr(api, "security_key_names", None):
            raise Unsupported("security key")
        if api.requires_2fa and getattr(api, "_trusted_device_bridge_state", None) is None:
            # Bridge bootstrap failed or timed out (pyicloud swallows it): the
            # code already on the device is checked through the legacy endpoint.
            api.use_existing_trusted_device_code()
        return api

    def needs_code(self, api):
        return bool(api.requires_2fa)

    def validate_code(self, api, code):
        if not api.validate_2fa_code(code):
            return False
        return api.is_trusted_session or api.trust_session()

    def finish(self, api):
        # Triggers the PCS device-consent flow (approve on an Apple device) and
        # proves the session can read Reminders before it is handed over.
        list(api.reminders.lists())


class AuthService:
    def __init__(self, user, apple_id, public_base, session_root, backend, clock=time.time, done_url=None):
        self.user = user
        self.apple_id = apple_id
        self.public_base = public_base.rstrip("/")
        self.root = Path(session_root)
        self.backend = backend
        self.clock = clock
        self.done_url = done_url
        self.lock = threading.Lock()
        self.login = None
        self.last_result = None

    # ---- MCP side ----
    def start(self):
        now = self.clock()
        with self.lock:
            # No rate limit: issuing a link does not contact Apple. A new link
            # replaces (and invalidates) any earlier one.
            self._discard_locked()
            token = secrets.token_urlsafe(32)
            self.login = Login(token, now)
        log("login_start")
        return {"ok": True, "url": f"{self.public_base}/{self.user}/{token}",
                "expires_in_seconds": TOKEN_TTL,
                "instructions": "Send this link to the user. They open it on their iPhone, fill the Apple ID "
                                "password, then enter the 2FA code or approve on a device if asked. "
                                "Call icloud_login_status afterwards, then retry the calendar/reminders tool."}

    def status(self):
        with self.lock:
            self._expire_locked()
            login = self.login
            state = login.state if login else "idle"
        return {"pending_login": state, "last_result": self.last_result,
                "session_present": any((self.root / "live").glob("*.session"))}

    # ---- web side ----
    def find(self, token):
        """Return the pending Login for this token, else None (-> link-expired page)."""
        with self.lock:
            self._expire_locked()
            login = self.login
            if login is None or login.state in ("done", "failed"):
                return None
            if not hmac.compare_digest(token.encode(), login.token.encode()):
                return None
            return login

    def watch(self, login):
        """True while this login is still the current one (for SSE streams)."""
        with self.lock:
            if self.login is login and login.expired(self.clock()):
                self._expire_locked()
            return self.login is login

    def submit_password(self, login, password):
        """Returns immediately; the whole Apple conversation runs in a worker thread."""
        with login.lock:
            if login.state != "link":
                return
            login.staging = Path(self._new_staging())
            login.set("signing_in")
        threading.Thread(target=self._run, args=(login, password), daemon=True).start()
        password = None

    def submit_code(self, login, code):
        """Queue the code; the worker submits it once pyicloud's prompt is ready."""
        with login.lock:
            if login.state not in ("code", "signing_in") or login.pending_code is not None:
                return
            login.pending_code = code
            login.set("verifying", "已收到验证码，正在提交给 Apple…")

    def _run(self, login, password):
        def on_need_code():
            with login.lock:
                if login.state == "signing_in":
                    login.set("code")
            log("login_need_code")

        try:
            api = self.backend.start(password, login.staging, on_need_code)
            password = None
            login.api = api
            if self.backend.needs_code(api):
                with login.lock:
                    if login.state == "signing_in":
                        login.set("code")
                self._code_loop(login)
            else:
                log("login_password_ok", next="approve")
            self._approve(login)
        except Exception as error:  # noqa: BLE001
            password = None
            self._fail(login, error)
        finally:
            login.api = None
            self._clear_if(login)

    def _code_loop(self, login):
        while True:
            with login.lock:
                while login.pending_code is None:
                    if login.state in ("done", "failed") or login.expired(self.clock()):
                        raise TimeoutError("code not entered")
                    login.changed.wait(timeout=1.0)
                code, login.pending_code = login.pending_code, None
            if self.backend.validate_code(login.api, code):
                log("login_code_ok")
                return
            login.code_attempts += 1
            if login.code_attempts >= MAX_CODE_ATTEMPTS:
                login.reason = "code"
                raise Unsupported("too many wrong codes")
            with login.lock:
                login.set("code", f"验证码不对，还可以再试 {MAX_CODE_ATTEMPTS - login.code_attempts} 次。")

    def _approve(self, login):
        with login.lock:
            login.set("approve")
        self.backend.finish(login.api)
        self._publish(login)
        self.last_result = {"result": "ok", "at": int(self.clock())}
        with login.lock:
            login.set("done")
        log("login_done")

    def _publish(self, login):
        incoming = self.root / "incoming"
        if incoming.exists():
            shutil.rmtree(incoming)
        files = [p for p in login.staging.iterdir() if p.name.endswith((".session", ".cookiejar"))]
        if not any(p.name.endswith(".session") for p in files):
            raise RuntimeError("no session produced")
        os.replace(login.staging, incoming)
        login.staging = None
        fd = os.open(incoming / "READY", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fsync(fd)
        os.close(fd)

    def _fail(self, login, error):
        name = type(error).__name__
        reason = login.reason or classify(error)
        login.api = None
        self.last_result = {"result": "failed", "reason": reason, "at": int(self.clock())}
        log("login_failed", error=name, reason=reason)
        if login.staging is not None:
            shutil.rmtree(login.staging, ignore_errors=True)
            login.staging = None
        with login.lock:
            if login.state != "failed":
                login.reason = reason
                login.set("failed", FAIL_COPY[reason])

    def _clear_if(self, login):
        # The token is single-use: once finished or failed it is gone.
        with self.lock:
            if self.login is login and login.state in ("done", "failed"):
                self.login = None

    def _expire_locked(self):
        if self.login is not None and self.login.expired(self.clock()):
            log("login_expired", state=self.login.state)
            self._discard_locked()

    def _discard_locked(self):
        login, self.login = self.login, None
        if login is not None:
            with login.lock:
                if login.state not in ("done", "failed"):
                    login.reason = "timeout"
                    login.set("failed", FAIL_COPY["timeout"])
            login.api = None
            if login.staging is not None:
                shutil.rmtree(login.staging, ignore_errors=True)
                login.staging = None

    def _new_staging(self):
        base = self.root / "staging"
        base.mkdir(mode=0o700, exist_ok=True)
        path = base / secrets.token_hex(8)
        path.mkdir(mode=0o700)
        # Seed with the current session so pyicloud sends the stored trust_token
        # ("trust this browser"); Apple then skips 2FA while that trust is valid.
        live = self.root / "live"
        if live.is_dir():
            for src in live.iterdir():
                if src.is_file() and src.name.endswith((".session", ".cookiejar")):
                    shutil.copyfile(src, path / src.name)
                    os.chmod(path / src.name, 0o600)
        return path


# ---------------------------------------------------------------- web pages
# One static page per login. The inline script (CSP nonce) only opens an
# EventSource and toggles which <section> is visible; forms are fetch() POSTs.
# No meta refresh, no polling. The only timer is the redirect after "done".
PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">
<meta name="color-scheme" content="light dark"><title>iCloud 登录</title>
<style>
:root{{--bg:#fff;--fg:#111;--muted:#666;--line:#ccc;--field:#fff;--accent:#0a84ff;--ok:#1a7f37;--bad:#c62828}}
@media(prefers-color-scheme:dark){{:root{{--bg:#000;--fg:#eee;--muted:#9a9a9a;--line:#444;--field:#1c1c1e;--ok:#4cc26a;--bad:#ff6b6b}}}}
body{{font:17px/1.5 -apple-system,system-ui,sans-serif;max-width:420px;margin:32px auto;padding:0 16px;color:var(--fg);background:var(--bg)}}
h2{{margin:0 0 12px}}
ol.steps{{display:flex;gap:6px;list-style:none;padding:0;margin:0 0 20px;font-size:13px;color:var(--muted)}}
ol.steps li{{flex:1;border-top:3px solid var(--line);padding-top:4px}}
ol.steps li.on{{border-color:var(--accent);color:var(--fg)}}
input,button{{font:inherit;width:100%;box-sizing:border-box;padding:12px;margin:8px 0;border-radius:10px;border:1px solid var(--line);background:var(--field);color:var(--fg)}}
button{{background:var(--accent);color:#fff;border:0}} button:disabled{{opacity:.5}}
.muted{{color:var(--muted);font-size:15px}} .msg{{color:var(--bad)}} .ok{{color:var(--ok)}}
section{{display:none}} section.on{{display:block}}
</style></head><body>
<h2>iCloud 登录（{user}）</h2>
<ol class="steps"><li data-s="1">密码</li><li data-s="2">验证码</li><li data-s="3">设备批准</li><li data-s="4">完成</li></ol>

<section id="s-link"><p>输入 Apple ID 密码。密码只用于这一次登录，不保存。</p>
<form id="f-pw" autocomplete="on">
<input type="text" name="username" autocomplete="username" value="{apple_id}" readonly hidden>
<input type="password" name="password" autocomplete="current-password" placeholder="Apple ID 密码" required autofocus>
<button type="submit">登录</button></form>
<p class="muted">没有自动填充？点密码框，键盘上方点「密码」或🔑，用面容 ID 解锁后搜索 <b>apple</b>，选你的 Apple ID。</p></section>

<section id="s-signing_in"><p>正在和 Apple 验证密码…</p>
<p class="muted">如果 iPhone 弹出「Apple ID 登录请求」，点<b>允许</b>，记下 6 位验证码。</p></section>

<section id="s-code"><p>输入 iPhone / Mac 上显示的 <b>6 位验证码</b>。</p>
<p class="muted">先在弹窗里点「允许」才会显示验证码。没收到：iPhone「设置 → 你的名字 → 登录与安全 → 获取验证码」。</p>
<p class="msg" id="code-msg"></p>
<form id="f-code"><input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"
pattern="[0-9]{{6}}" maxlength="6" placeholder="6 位验证码" required>
<button type="submit">验证</button></form></section>

<section id="s-verifying"><p>已收到验证码，正在提交给 Apple…</p></section>

<section id="s-approve"><p>如果 iPhone / Mac 上弹出「允许访问 iCloud 数据」，请点<b>允许</b>。</p>
<p class="muted">没有弹窗也没关系，通常几秒内会自动完成；最长等待约 1 分钟。</p></section>

<section id="s-done"><p class="ok">✅ 登录完成，可以回到对话了。</p><p class="muted" id="done-hint">本页即将关闭。</p></section>

<section id="s-failed"><p class="msg" id="fail-msg">登录失败。</p>
<p>请回到对话，让助手重新发起登录，用新链接再试一次。</p></section>

<section id="s-gone"><p>链接已失效。</p><p>请回到对话，让助手重新发起登录。</p></section>

<script nonce="{nonce}">
(function(){{
  var STEP={{link:1,signing_in:1,code:2,verifying:2,approve:3,done:4,failed:0,gone:0}};
  var base=location.pathname.replace(/\\/$/,""), doneUrl={done_url}, es=null, closed=false;
  function show(st,msg){{
    document.querySelectorAll("section").forEach(function(s){{s.classList.toggle("on",s.id==="s-"+st)}});
    document.querySelectorAll("ol.steps li").forEach(function(li){{li.classList.toggle("on",+li.dataset.s<=STEP[st])}});
    if(st==="code"){{document.getElementById("code-msg").textContent=msg||"";var c=document.querySelector("#f-code input");c.value="";c.focus()}}
    if(st==="failed"&&msg){{document.getElementById("fail-msg").textContent=msg}}
    if(st==="done"||st==="failed"||st==="gone"){{stop()}}
    if(st==="done"){{finish()}}
  }}
  function stop(){{closed=true;if(es){{es.close()}}}}
  function finish(){{
    window.close();
    setTimeout(function(){{
      if(doneUrl){{document.getElementById("done-hint").textContent="正在返回聊天…";location.replace(doneUrl)}}
      else{{document.getElementById("done-hint").textContent="可以关闭本页。"}}
    }},2000);
  }}
  function post(form){{
    var b=form.querySelector("button");b.disabled=true;
    fetch(base,{{method:"POST",credentials:"same-origin",body:new URLSearchParams(new FormData(form))}})
      .then(function(r){{if(r.status===404){{show("gone")}}}})
      .catch(function(){{}}).finally(function(){{b.disabled=false}});
  }}
  document.getElementById("f-pw").addEventListener("submit",function(e){{e.preventDefault();post(this);show("signing_in")}});
  document.getElementById("f-code").addEventListener("submit",function(e){{e.preventDefault();post(this);show("verifying")}});
  es=new EventSource(base+"/events");
  es.onmessage=function(e){{if(!closed){{var d=JSON.parse(e.data);show(d.state,d.message)}}}};
  es.addEventListener("gone",function(){{if(!closed){{show("gone")}}}});
  show({initial});
}})();
</script></body></html>"""

GONE_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<meta name="color-scheme" content="light dark"><title>链接已失效</title>
<style>body{font:17px/1.5 -apple-system,system-ui,sans-serif;max-width:420px;margin:40px auto;padding:0 16px}
@media(prefers-color-scheme:dark){body{background:#000;color:#eee}}</style></head>
<body><h2>链接已失效</h2><p>这个登录链接已过期或已使用。</p><p>请回到对话，让助手重新发起登录。</p></body></html>"""


def render(svc, login, nonce):
    return PAGE.format(user=html.escape(svc.user), apple_id=html.escape(svc.apple_id), nonce=nonce,
                       done_url=json.dumps(svc.done_url or ""), initial=json.dumps(login.state))


def make_web_handler(svc):
    class Web(BaseHTTPRequestHandler):
        server_version = "icloud-auth"
        sys_version = ""

        def log_message(self, *args):  # default logger prints the full path (token)
            pass

        def _access(self, status):
            path = self.path.split("?", 1)[0]
            masked = "/" + path.strip("/").split("/", 1)[0] + "/…" if path.count("/") > 1 else path
            log("http", method=self.command, path=masked, status=status)

        def _headers(self, status, ctype, length=None, cookie=None, nonce=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            if length is not None:
                self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            script = f"'nonce-{nonce}'" if nonce else "'none'"
            self.send_header("Content-Security-Policy",
                             f"default-src 'none'; style-src 'unsafe-inline'; script-src {script}; "
                             "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            if cookie:
                self.send_header("Set-Cookie", f"icloud_auth={cookie}; Path=/{svc.user}/; HttpOnly; Secure; SameSite=Strict; Max-Age={FLOW_TTL}")

        def _send(self, status, body="", cookie=None, nonce=None):
            data = body.encode()
            self._headers(status, "text/html; charset=utf-8", len(data), cookie, nonce)
            self.end_headers()
            self.wfile.write(data)
            self._access(status)

        def _gone(self):
            # One page for unknown, used and expired links: it reveals nothing
            # about whether a token ever existed. Status stays 404.
            self._send(404, GONE_PAGE)

        def _route(self):
            """(login, is_events) for /<user>/<token>[/events]; login None when invalid."""
            path = self.path.split("?", 1)[0]
            prefix = f"/{svc.user}/"
            if not path.startswith(prefix):
                return None, False
            rest = path[len(prefix):]
            events = rest.endswith("/events")
            token = rest[: -len("/events")] if events else rest
            if not token or "/" in token:
                return None, events
            return svc.find(token), events

        def _cookie_ok(self, login):
            raw = self.headers.get("Cookie", "")
            for part in raw.split(";"):
                name, _, value = part.strip().partition("=")
                if name == "icloud_auth" and hmac.compare_digest(value.encode(), login.cookie.encode()):
                    return True
            return False

        def do_GET(self):
            login, events = self._route()
            if login is None:
                return self._gone()
            if events:
                if not self._cookie_ok(login):
                    return self._gone()
                return self._stream(login)
            nonce = secrets.token_urlsafe(16)
            if login.state == "link":
                # First visit binds the browser; a leaked URL alone cannot be continued elsewhere.
                return self._send(200, render(svc, login, nonce), cookie=login.cookie, nonce=nonce)
            if not self._cookie_ok(login):
                return self._gone()
            self._send(200, render(svc, login, nonce), nonce=nonce)

        def _stream(self, login):
            """Server-sent events: current state on connect, then every change, then end."""
            self._headers(200, "text/event-stream; charset=utf-8")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.close_connection = True
            self._access(200)
            seen = -1
            try:
                while True:
                    with login.lock:
                        if login.version == seen:
                            login.changed.wait(timeout=SSE_HEARTBEAT)
                        current, snap = login.version, login.snapshot()
                    terminal = snap["state"] in ("done", "failed")
                    if current != seen:
                        seen = current
                        self.wfile.write(f"data: {json.dumps(snap, ensure_ascii=False)}\n\n".encode())
                    elif not svc.watch(login) and not terminal:
                        # Replaced by a newer link or expired without a final event.
                        self.wfile.write(b"event: gone\ndata: {}\n\n")
                        self.wfile.flush()
                        return
                    else:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    if terminal:
                        return
            except (BrokenPipeError, ConnectionResetError):
                return

        def do_POST(self):
            login, events = self._route()
            if login is None or events or not self._cookie_ok(login):
                return self._gone()
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._gone()
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"), max_num_fields=4)
            if login.state == "link" and form.get("password"):
                svc.submit_password(login, form["password"][0])
            elif form.get("code"):
                code = form["code"][0].strip()
                if code.isdigit() and len(code) == 6:
                    svc.submit_code(login, code)
            form = None
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self._access(204)

        def do_PUT(self):
            self._gone()

        do_DELETE = do_PATCH = do_HEAD = do_PUT

    return Web


# ---------------------------------------------------------------- MCP side
TOOLS = [
    {"name": "icloud_login_start",
     "description": "Start an iCloud login when calendar/reminders tools report that the Apple login session "
                    "is missing or expired. Returns a one-time link (valid 5 minutes) to show to the user. "
                    "A new link replaces any earlier one; do not call it again while the user is logging in.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}},
    {"name": "icloud_login_status",
     "description": "Check whether a login is pending and whether the last login finished. Returns no secrets.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
]


def mcp_dispatch(svc, message):
    method, mid = message.get("method"), message.get("id")
    if mid is None:
        return None  # notification
    if method == "initialize":
        result = {"protocolVersion": message.get("params", {}).get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": "icloud-auth", "version": "1"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name = message.get("params", {}).get("name")
        if name == "icloud_login_start":
            out = svc.start()
        elif name == "icloud_login_status":
            out = svc.status()
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        result = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}],
                  "structuredContent": out, "isError": not out.get("ok", True)}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def make_mcp_handler(svc, allowed_hosts):
    class Mcp(BaseHTTPRequestHandler):
        server_version = "icloud-auth-mcp"
        sys_version = ""

        def log_message(self, *args):
            pass

        def _reply(self, status, payload=None):
            data = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            if payload is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _guard(self):
            if self.headers.get("Host") not in allowed_hosts or self.headers.get("Origin"):
                self._reply(403)
                return False
            if self.path.split("?", 1)[0] != "/mcp":
                self._reply(404)
                return False
            return True

        def do_GET(self):
            if self.path == "/healthz":
                return self._reply(200, {"status": "ok"})
            if self._guard():
                self._reply(405)

        do_DELETE = do_GET

        def do_POST(self):
            if not self._guard():
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 65536:
                return self._reply(413)
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError:
                return self._reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            if isinstance(body, list):
                replies = [r for r in (mcp_dispatch(svc, m) for m in body) if r]
                return self._reply(200, replies) if replies else self._reply(202)
            reply = mcp_dispatch(svc, body)
            if reply is None:
                return self._reply(202)
            self._reply(200, reply)

    return Mcp


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main():
    logging.disable(logging.CRITICAL)
    threading.excepthook = safe_excepthook
    sys.excepthook = lambda t, v, tb: log("fatal", error=t.__name__)
    os.umask(0o077)
    user = os.environ["ICLOUD_AUTH_USER"]
    apple_id = os.environ["ICLOUD_APPLE_ID"]
    root = Path(os.environ["ICLOUD_SESSION_ROOT"])
    (root / "live").mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.rmtree(root / "staging", ignore_errors=True)  # half-finished logins from a previous run
    svc = AuthService(user, apple_id, os.environ["ICLOUD_AUTH_PUBLIC_BASE"], root, PyiCloudBackend(apple_id),
                      done_url=os.environ.get("ICLOUD_AUTH_DONE_URL") or None)
    hosts = {h.strip() for h in os.environ["ICLOUD_AUTH_MCP_ALLOWED_HOSTS"].split(",") if h.strip()}
    web = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("ICLOUD_AUTH_WEB_PORT", "8000"))), make_web_handler(svc))
    mcp = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("ICLOUD_AUTH_MCP_PORT", "8001"))), make_mcp_handler(svc, hosts))
    for s in (web, mcp):
        s.daemon_threads = True
        s.handle_error = lambda request, address: log("handler_error", error=type(sys.exc_info()[1]).__name__)
    log("started", user=user)
    serve(mcp)
    web.serve_forever()


if __name__ == "__main__":
    main()
