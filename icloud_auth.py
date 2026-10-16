#!/usr/bin/env python3
"""icloud-auth: one-time link login for the iCloud MCP (no password at rest).

Two listeners in one process:
  :8000  login page, reachable from the internet via ingress. 404 unless a
         pending one-time token matches.
  :8001  MCP (Streamable HTTP, stateless JSON) for Open WebUI:
         icloud_login_start / icloud_login_status.

The password only exists in the POST handler's locals and inside the
PyiCloudService object for the duration of one login. Nothing logs it: Python
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


def log(event, **fields):
    """The only log sink. Never pass secrets here."""
    record = {"ts": int(time.time()), "event": event, **fields}
    print(json.dumps(record, ensure_ascii=False), file=sys.stderr, flush=True)


def safe_excepthook(args):
    log("thread_error", error=type(args.exc_value).__name__)


class Login:
    """One pending login. State: link -> password -> (code) -> (approve) -> done|failed."""

    def __init__(self, token, now):
        self.token = token
        self.cookie = secrets.token_urlsafe(24)
        self.created = now
        self.state = "link"
        self.message = ""
        self.api = None
        self.staging = None
        self.code_attempts = 0
        self.lock = threading.Lock()

    def expired(self, now):
        if self.state == "link":
            return now - self.created > TOKEN_TTL
        return now - self.created > FLOW_TTL


class PyiCloudBackend:
    """Thin seam over pyicloud so tests can run without an Apple account."""

    def __init__(self, apple_id):
        self.apple_id = apple_id

    def login(self, password, staging):
        from pyicloud import PyiCloudService
        api = PyiCloudService(self.apple_id, password=password, cookie_directory=str(staging),
                              with_family=False, accept_terms=False)
        # SRP is done; later steps (2FA, trust, PCS) only use session tokens.
        api._password_raw = None
        if api.requires_2sa and not api.requires_2fa:
            raise Unsupported("legacy two-step verification is not supported")
        if api.requires_2fa:
            if getattr(api, "security_key_names", None):
                raise Unsupported("security-key accounts are not supported")
            if not api.request_2fa_code():
                raise Unsupported("this 2FA challenge needs a security key")
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


class Unsupported(Exception):
    pass


class AuthService:
    def __init__(self, user, apple_id, public_base, session_root, backend, clock=time.time):
        self.user = user
        self.apple_id = apple_id
        self.public_base = public_base.rstrip("/")
        self.root = Path(session_root)
        self.backend = backend
        self.clock = clock
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
    def find(self, path):
        """Return the pending Login for /<user>/<token>, else None (-> 404)."""
        prefix = f"/{self.user}/"
        if not path.startswith(prefix):
            return None
        token = path[len(prefix):]
        with self.lock:
            self._expire_locked()
            login = self.login
            if login is None or login.state in ("done", "failed"):
                return None
            if not hmac.compare_digest(token.encode(), login.token.encode()):
                return None
            return login

    def submit_password(self, login, password):
        with login.lock:
            if login.state != "link":
                return
            login.state = "working"
            login.staging = Path(self._new_staging())
        try:
            api = self.backend.login(password, login.staging)
            password = None
            if self.backend.needs_code(api):
                login.api = api
                login.state = "code"
                log("login_password_ok", next="code")
                return
            login.api = api
            self._finish_async(login)
        except Exception as error:  # noqa: BLE001
            password = None
            self._fail(login, error)

    def submit_code(self, login, code):
        with login.lock:
            if login.state != "code":
                return
            login.state = "working"
        try:
            if self.backend.validate_code(login.api, code):
                log("login_code_ok")
                self._finish_async(login)
                return
            login.code_attempts += 1
            if login.code_attempts >= MAX_CODE_ATTEMPTS:
                self._fail(login, Unsupported("too many wrong codes"))
                return
            login.state = "code"
            login.message = f"验证码不对，还可以再试 {MAX_CODE_ATTEMPTS - login.code_attempts} 次。"
        except Exception as error:  # noqa: BLE001
            self._fail(login, error)

    def _finish_async(self, login):
        login.state = "approve"

        def run():
            try:
                self.backend.finish(login.api)
                self._publish(login)
                login.state = "done"
                self.last_result = {"result": "ok", "at": int(self.clock())}
                log("login_done")
            except Exception as error:  # noqa: BLE001
                self._fail(login, error)
            finally:
                login.api = None
                self._clear_if(login)

        threading.Thread(target=run, daemon=True).start()

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
        login.state = "failed"
        login.api = None
        login.message = str(error) if isinstance(error, Unsupported) else "登录失败。"
        self.last_result = {"result": "failed", "reason": name, "at": int(self.clock())}
        log("login_failed", error=name)
        if login.staging is not None:
            shutil.rmtree(login.staging, ignore_errors=True)
            login.staging = None
        self._clear_if(login)

    def _clear_if(self, login):
        # The token is single-use: once finished or failed it is gone (404).
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
            login.api = None
            if login.staging is not None:
                shutil.rmtree(login.staging, ignore_errors=True)

    def _new_staging(self):
        base = self.root / "staging"
        base.mkdir(mode=0o700, exist_ok=True)
        path = base / secrets.token_hex(8)
        path.mkdir(mode=0o700)
        return path


# ---------------------------------------------------------------- web pages
PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">
{refresh}<title>iCloud 登录</title>
<style>body{{font:17px -apple-system,system-ui,sans-serif;max-width:420px;margin:40px auto;padding:0 16px;color:#111;background:#fff}}
input,button{{font:inherit;width:100%;box-sizing:border-box;padding:12px;margin:8px 0;border-radius:10px;border:1px solid #bbb}}
button{{background:#0a84ff;color:#fff;border:0}}.msg{{color:#c00}}
@media(prefers-color-scheme:dark){{body{{background:#000;color:#eee}}input{{background:#1c1c1e;color:#eee;border-color:#444}}}}</style>
</head><body><h2>iCloud 登录（{user}）</h2>{body}</body></html>"""

PASSWORD_FORM = """<p>输入 Apple ID 密码。密码只用于这一次登录，不保存。</p>
<form method="post" autocomplete="on">
<input type="text" name="username" autocomplete="username" value="{apple_id}" readonly hidden>
<input type="password" name="password" autocomplete="current-password" placeholder="Apple ID 密码" required autofocus>
<button type="submit">登录</button></form>"""

CODE_FORM = """<p>Apple 已向你的设备发送 6 位验证码。</p><p class="msg">{msg}</p>
<form method="post"><input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"
pattern="[0-9]{{6}}" maxlength="6" placeholder="6 位验证码" required autofocus>
<button type="submit">验证</button></form>"""


def render(user, body, refresh=False):
    return PAGE.format(user=html.escape(user), body=body,
                       refresh='<meta http-equiv="refresh" content="3">' if refresh else "")


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

        def _send(self, status, body="", cookie=None):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            if cookie:
                self.send_header("Set-Cookie", f"icloud_auth={cookie}; Path=/{svc.user}/; HttpOnly; Secure; SameSite=Strict; Max-Age={FLOW_TTL}")
            self.end_headers()
            self.wfile.write(data)
            self._access(status)

        def _not_found(self):
            self._send(404, "Not Found")

        def _cookie_ok(self, login):
            raw = self.headers.get("Cookie", "")
            for part in raw.split(";"):
                name, _, value = part.strip().partition("=")
                if name == "icloud_auth" and hmac.compare_digest(value.encode(), login.cookie.encode()):
                    return True
            return False

        def _page(self, login):
            state = login.state
            if state == "link":
                return render(svc.user, PASSWORD_FORM.format(apple_id=html.escape(svc.apple_id)))
            if state == "code":
                return render(svc.user, CODE_FORM.format(msg=html.escape(login.message)))
            if state == "approve":
                return render(svc.user, "<p>如果 iPhone / Mac 上弹出「允许访问 iCloud 数据」的请求，请点<b>允许</b>。</p>"
                                        "<p>本页会自动刷新。</p>", refresh=True)
            return render(svc.user, "<p>处理中…</p>", refresh=True)

        def do_GET(self):
            login = svc.find(self.path.split("?", 1)[0])
            if login is None:
                return self._not_found()
            if login.state == "link":
                # First visit binds the browser; a leaked URL alone cannot be continued elsewhere.
                return self._send(200, self._page(login), cookie=login.cookie)
            if not self._cookie_ok(login):
                return self._not_found()
            self._send(200, self._page(login))

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            login = svc.find(path)
            if login is None or not self._cookie_ok(login):
                return self._not_found()
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._not_found()
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"), max_num_fields=4)
            if login.state == "link" and form.get("password"):
                svc.submit_password(login, form["password"][0])
                form = None
            elif login.state == "code" and form.get("code"):
                code = form["code"][0].strip()
                if code.isdigit() and len(code) == 6:
                    svc.submit_code(login, code)
            if login.state == "done":
                body = render(svc.user, "<p>✅ 登录完成，可以回到对话了。</p>")
            elif login.state == "failed":
                body = render(svc.user, f"<p class=\"msg\">{html.escape(login.message)}</p><p>请回到对话让助手重新发起登录。</p>")
            else:
                body = self._page(login)
            self._send(200, body)

        do_PUT = do_DELETE = do_PATCH = do_HEAD = lambda self: self._not_found()  # noqa: E731

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
    svc = AuthService(user, apple_id, os.environ["ICLOUD_AUTH_PUBLIC_BASE"], root, PyiCloudBackend(apple_id))
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
