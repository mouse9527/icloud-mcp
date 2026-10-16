"""Offline tests for icloud_auth.py and reminders_worker_reload.py (no Apple account).

Run:  UPSTREAM_SCRIPTS=<icloud-mcp checkout>/scripts python3 -m pytest -q tests/
"""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import urllib.parse

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, os.environ.get("UPSTREAM_SCRIPTS", str(HERE / "upstream-scripts")))

import icloud_auth  # noqa: E402

MARKER = "PW-MARKER-" + os.urandom(6).hex()  # stands in for a password; must never surface
APPLE_ID = "user@example.com"


class FakeBackend:
    """Mimics PyiCloudBackend. Gates let a test hold the worker at a given step:
    srp_gate     -> before pyicloud would decide a code is needed
    bridge_gate  -> after on_need_code(), while the trusted-device bridge waits
    finish_gate  -> during device approval (PCS)
    """

    def __init__(self, need_code=False, good_code="123456", fail_login=None, gated=False):
        self.need_code, self.good_code, self.fail_login = need_code, good_code, fail_login
        self.passwords, self.codes = [], []
        self.gates = {k: threading.Event() for k in ("srp_gate", "bridge_gate", "finish_gate")}
        if not gated:
            for g in self.gates.values():
                g.set()

    def release(self, name):
        self.gates[name].set()

    def start(self, password, staging, on_need_code):
        self.passwords.append(password)
        self.seen_in_staging = sorted(p.name for p in staging.iterdir())
        assert self.gates["srp_gate"].wait(5)
        if self.fail_login:
            raise self.fail_login("upstream said: bad password " + password)  # must not leak
        if self.need_code:
            on_need_code()
            assert self.gates["bridge_gate"].wait(5)
        (staging / "userexamplecom.session").write_text(json.dumps({"session_token": "synthetic"}))
        (staging / "userexamplecom.cookiejar").write_text("#LWP-Cookies-2.0\n")
        return object()

    def needs_code(self, api):
        return self.need_code

    def validate_code(self, api, code):
        self.codes.append(code)
        return code == self.good_code

    def finish(self, api):
        assert self.gates["finish_gate"].wait(5)


class PyiCloudFailedLoginException(Exception):
    """Same class name pyicloud raises for a wrong password."""


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


@contextlib.contextmanager
def running(backend, tmp_path, clock=None, done_url=None):
    stderr = io.StringIO()
    old = sys.stderr
    sys.stderr = stderr
    (tmp_path / "live").mkdir(mode=0o700)
    svc = icloud_auth.AuthService("alice", APPLE_ID, "https://icloud-auth.example:1443",
                                  tmp_path, backend, clock or time.time, done_url=done_url)
    web = icloud_auth.ThreadingHTTPServer(("127.0.0.1", 0), icloud_auth.make_web_handler(svc))
    mcp = icloud_auth.ThreadingHTTPServer(("127.0.0.1", 0), icloud_auth.make_mcp_handler(svc, {"icloud-mcp:8001"}))
    for s in (web, mcp):
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        yield svc, web.server_address[1], mcp.server_address[1], stderr
    finally:
        web.shutdown()
        mcp.shutdown()
        sys.stderr = old


def req(port, method, path, body=None, headers=None, timeout=5):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read().decode()
    return r.status, data, r.getheader("Set-Cookie")


def mcp_call(port, name, host="icloud-mcp:8001"):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}})
    status, data, _ = req(port, "POST", "/mcp", body, {"Host": host, "Content-Type": "application/json"})
    return status, (json.loads(data) if data else None)


def start_link(mport):
    _, reply = mcp_call(mport, "icloud_login_start")
    out = reply["result"]["structuredContent"]
    assert out["ok"], out
    return urllib.parse.urlparse(out["url"]).path


def open_link(wport, path):
    status, page, cookie = req(wport, "GET", path)
    assert status == 200
    return page, cookie.split(";")[0]


def post(wport, path, cookie, **fields):
    return req(wport, "POST", path, urllib.parse.urlencode(fields),
               {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})


class Events:
    """Reads one SSE stream in a thread; collects data events and the raw text."""

    def __init__(self, wport, path, cookie):
        self.conn = http.client.HTTPConnection("127.0.0.1", wport, timeout=10)
        self.conn.request("GET", path + "/events", headers={"Cookie": cookie, "Accept": "text/event-stream"})
        self.resp = self.conn.getresponse()
        self.status = self.resp.status
        self.ctype = self.resp.getheader("Content-Type")
        self.raw, self.states, self.ended = "", [], threading.Event()
        self.cond = threading.Condition()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        try:
            while True:
                line = self.resp.fp.readline()
                if not line:
                    break
                text = line.decode()
                with self.cond:
                    self.raw += text
                    if text.startswith("data: ") and text.strip() != "data: {}":
                        self.states.append(json.loads(text[6:])["state"])
                    elif text.startswith("event: gone"):
                        self.states.append("gone")
                    self.cond.notify_all()
        except OSError:
            pass
        finally:
            self.ended.set()

    def wait_for(self, state, timeout=5):
        with self.cond:
            assert self.cond.wait_for(lambda: state in self.states, timeout), (state, self.states)


def wait_result(svc, want, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        r = svc.status()["last_result"]
        if r and r["result"] == want:
            return r
        time.sleep(0.02)
    raise AssertionError(svc.status())


# ---------------------------------------------------------------- link / page
def test_everything_404_without_pending_token(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        for path in ["/", "/alice", "/alice/", "/alice/" + "x" * 43, "/bob/abc", "/healthz", "/../etc/passwd",
                     "/alice/x/events", "/alice//events"]:
            status, page, _ = req(wport, "GET", path)
            assert status == 404 and "链接已失效" in page, path
            assert req(wport, "POST", path, "password=x")[0] == 404, path


def test_expired_and_unknown_links_get_the_same_friendly_page(tmp_path):
    clock = Clock()
    with running(FakeBackend(), tmp_path, clock) as (svc, wport, mport, _):
        unknown = req(wport, "GET", "/alice/never-existed")
        path = start_link(mport)
        clock.now += icloud_auth.TOKEN_TTL + 1
        expired = req(wport, "GET", path)
        assert unknown[0] == expired[0] == 404 and unknown[1] == expired[1]


def test_wrong_token_404_and_page_has_autofill_fields(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        assert req(wport, "GET", "/alice/wrong")[0] == 404
        assert req(wport, "GET", path.replace("/alice/", "/bob/"))[0] == 404
        page, cookie = open_link(wport, path)
        assert 'autocomplete="username"' in page and 'autocomplete="current-password"' in page
        assert f'value="{APPLE_ID}"' in page and "hidden" in page
        assert "钥匙" in page or "🔑" in page          # keychain hint


def test_page_has_no_polling_and_csp_nonce(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        c = http.client.HTTPConnection("127.0.0.1", wport, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        page, csp = r.read().decode(), r.getheader("Content-Security-Policy")
        assert 'http-equiv="refresh"' not in page
        assert "setInterval" not in page and "XMLHttpRequest" not in page
        assert "EventSource" in page
        nonce = re.search(r'<script nonce="([^"]+)">', page).group(1)
        assert f"'nonce-{nonce}'" in csp and "connect-src 'self'" in csp
        assert "http://" not in page and "https://" not in page.replace(APPLE_ID, "")  # no external resources


def test_post_requires_binding_cookie(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        open_link(wport, path)
        status, _, _ = post(wport, path, "icloud_auth=forged", password=MARKER)
        assert status == 404


def test_token_expires_after_5_minutes(tmp_path):
    clock = Clock()
    with running(FakeBackend(), tmp_path, clock) as (svc, wport, mport, _):
        path = start_link(mport)
        clock.now += icloud_auth.TOKEN_TTL + 1
        assert req(wport, "GET", path)[0] == 404


def test_login_start_new_link_replaces_old(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        first = start_link(mport)
        second = start_link(mport)
        assert first != second
        assert req(wport, "GET", first)[0] == 404
        assert req(wport, "GET", second)[0] == 200


# ---------------------------------------------------------------- SSE
def test_events_endpoint_requires_token_and_cookie(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        assert req(wport, "GET", path + "/events")[0] == 404                                   # no cookie
        assert req(wport, "GET", path + "/events", headers={"Cookie": "icloud_auth=forged"})[0] == 404
        assert req(wport, "GET", "/alice/wrong/events", headers={"Cookie": cookie})[0] == 404
        ev = Events(wport, path, cookie)
        assert ev.status == 200 and ev.ctype.startswith("text/event-stream")
        ev.wait_for("link")                                                                    # current state on connect
        ev.conn.close()


def test_password_post_returns_immediately_and_code_form_comes_before_bridge(tmp_path):
    backend = FakeBackend(need_code=True, gated=True)
    with running(backend, tmp_path) as (svc, wport, mport, stderr):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        ev = Events(wport, path, cookie)
        ev.wait_for("link")
        t0 = time.time()
        status, _, _ = post(wport, path, cookie, username=APPLE_ID, password=MARKER)
        assert status == 204 and time.time() - t0 < 1.0          # SRP is still blocked in the backend
        ev.wait_for("signing_in")
        backend.release("srp_gate")
        ev.wait_for("code")                                      # bridge still blocked: form already shown
        assert not backend.gates["bridge_gate"].is_set()
        # a code typed before the bridge is ready is queued, not validated yet
        assert post(wport, path, cookie, code="123456")[0] == 204
        ev.wait_for("verifying")
        time.sleep(0.2)
        assert backend.codes == []
        backend.release("bridge_gate")
        ev.wait_for("approve")
        assert backend.codes == ["123456"]
        backend.release("finish_gate")
        ev.wait_for("done")
        assert ev.ended.wait(3)                                  # stream closes after the final event
        order = [s for i, s in enumerate(ev.states) if s not in ev.states[:i]]
        assert order == ["link", "signing_in", "code", "verifying", "approve", "done"]
        assert APPLE_ID not in ev.raw and MARKER not in ev.raw and path.rsplit("/", 1)[1] not in ev.raw
        assert (tmp_path / "incoming" / "READY").exists()
        assert req(wport, "GET", path)[0] == 404                 # single use
        logs = stderr.getvalue()
    assert MARKER not in logs and APPLE_ID not in logs


def test_wrong_code_then_retry_in_place(tmp_path):
    backend = FakeBackend(need_code=True)
    with running(backend, tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        ev = Events(wport, path, cookie)
        post(wport, path, cookie, password=MARKER)
        ev.wait_for("code")
        post(wport, path, cookie, code="000000")
        end = time.time() + 5
        while len(backend.codes) < 1 and time.time() < end:
            time.sleep(0.02)
        with svc.login.lock:
            state, msg = svc.login.state, svc.login.message
        assert state == "code" and "还可以再试 2 次" in msg
        post(wport, path, cookie, code="123456")
        ev.wait_for("done")
        assert backend.codes == ["000000", "123456"]


def test_three_wrong_codes_fail_with_code_reason(tmp_path):
    backend = FakeBackend(need_code=True)
    with running(backend, tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        ev = Events(wport, path, cookie)
        post(wport, path, cookie, password=MARKER)
        for _ in range(3):
            ev.wait_for("code")
            n = len(backend.codes)
            post(wport, path, cookie, code="999999")
            end = time.time() + 5
            while len(backend.codes) == n and time.time() < end:
                time.sleep(0.02)
        ev.wait_for("failed")
        assert wait_result(svc, "failed")["reason"] == "code"
        assert icloud_auth.FAIL_COPY["code"] in ev.raw
        assert req(wport, "GET", path)[0] == 404


@pytest.mark.parametrize("exc, reason", [
    (PyiCloudFailedLoginException, "password"),
    (TimeoutError, "timeout"),
    (icloud_auth.Unsupported, "unsupported"),
    (RuntimeError, "apple"),
])
def test_failures_are_classified_and_hide_upstream_text(tmp_path, exc, reason):
    with running(FakeBackend(fail_login=exc), tmp_path) as (svc, wport, mport, stderr):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        ev = Events(wport, path, cookie)
        post(wport, path, cookie, password=MARKER)
        ev.wait_for("failed")
        assert icloud_auth.FAIL_COPY[reason] in ev.raw
        assert MARKER not in ev.raw and "upstream said" not in ev.raw
        assert wait_result(svc, "failed")["reason"] == reason
        assert req(wport, "GET", path)[0] == 404
        assert not (tmp_path / "incoming").exists()
        assert list((tmp_path / "staging").iterdir()) == []
        logs = stderr.getvalue()
    assert MARKER not in logs and "upstream said" not in logs


def test_stream_reports_gone_when_link_replaced(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        ev = Events(wport, path, cookie)
        ev.wait_for("link")
        start_link(mport)                       # a new link invalidates this one
        ev.wait_for("failed")                   # pushed immediately, no polling
        assert ev.ended.wait(3)


def test_flow_expiry_ends_waiting_for_code(tmp_path):
    clock = Clock()
    backend = FakeBackend(need_code=True)
    with running(backend, tmp_path, clock) as (svc, wport, mport, _):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        ev = Events(wport, path, cookie)
        post(wport, path, cookie, password=MARKER)
        ev.wait_for("code")
        clock.now += icloud_auth.FLOW_TTL + 1
        ev.wait_for("failed", timeout=5)
        assert wait_result(svc, "failed")["reason"] == "timeout"


def test_done_url_is_rendered_only_when_configured(tmp_path):
    with running(FakeBackend(), tmp_path, done_url="https://chat.example/") as (svc, wport, mport, _):
        page, _ = open_link(wport, start_link(mport))
        assert '"https://chat.example/"' in page and "window.close()" in page


# ---------------------------------------------------------------- session files
def test_full_login_writes_session_and_nothing_leaks(tmp_path):
    backend = FakeBackend(need_code=True)
    with running(backend, tmp_path) as (svc, wport, mport, stderr):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        post(wport, path, cookie, username=APPLE_ID, password=MARKER)
        end = time.time() + 5
        while svc.status()["pending_login"] != "code" and time.time() < end:
            time.sleep(0.02)
        post(wport, path, cookie, code="123456")
        wait_result(svc, "ok")
        assert backend.passwords == [MARKER]
        assert (tmp_path / "incoming" / "userexamplecom.session").exists()
        assert post(wport, path, cookie, password=MARKER)[0] == 404
        _, status_reply = mcp_call(mport, "icloud_login_status")
        text = json.dumps(status_reply)
        assert path.rsplit("/", 1)[1] not in text and MARKER not in text and APPLE_ID not in text
        logs = stderr.getvalue()
    assert MARKER not in logs and path.rsplit("/", 1)[1] not in logs
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert MARKER not in f.read_text(errors="ignore"), f


def test_staging_is_seeded_from_live_session(tmp_path):
    backend = FakeBackend()
    with running(backend, tmp_path) as (svc, wport, mport, _):
        live = tmp_path / "live"
        (live / "userexamplecom.session").write_text(json.dumps({"trust_token": "synthetic-trust"}))
        (live / "userexamplecom.cookiejar").write_text("#LWP-Cookies-2.0\n")
        (live / "mcp-receipts").mkdir()
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        post(wport, path, cookie, password=MARKER)
        wait_result(svc, "ok")
        assert backend.seen_in_staging == ["userexamplecom.cookiejar", "userexamplecom.session"]
        assert json.loads((live / "userexamplecom.session").read_text()) == {"trust_token": "synthetic-trust"}


def test_staging_empty_without_live_session(tmp_path):
    backend = FakeBackend()
    with running(backend, tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        post(wport, path, cookie, password=MARKER)
        wait_result(svc, "ok")
        assert backend.seen_in_staging == []


def test_mcp_guards(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        assert mcp_call(mport, "icloud_login_status", host="evil:8001")[0] == 403
        assert req(mport, "POST", "/mcp", "{}", {"Host": "icloud-mcp:8001", "Origin": "http://x", "Content-Length": "2"})[0] == 403
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        status, data, _ = req(mport, "POST", "/mcp", body, {"Host": "icloud-mcp:8001"})
        assert status == 200 and {t["name"] for t in json.loads(data)["result"]["tools"]} == {"icloud_login_start", "icloud_login_status"}
        # the login web port does not speak MCP and the MCP port has no login pages
        assert req(wport, "POST", "/mcp", body)[0] == 404
        assert req(mport, "GET", "/alice/x", headers={"Host": "icloud-mcp:8001"})[0] == 404


# ---------------------------------------------------------------- PyiCloudBackend hook
def test_pyicloud_backend_signals_code_before_bridge_returns(tmp_path, monkeypatch):
    """The instance-level request_2fa_code swap fires on_need_code before the
    original (blocking) bridge call, without changing pyicloud's source."""
    calls = []

    class FakeService:
        def __init__(self, apple_id, password=None, cookie_directory=None, **kw):
            assert kw.get("authenticate") is False
            self._password_raw = password
            self.requires_2sa = self.requires_2fa = True
            self.security_key_names = None
            self._trusted_device_bridge_state = "ready"

        def request_2fa_code(self):
            calls.append("bridge")
            return True

        def authenticate(self):
            assert self._password_raw == MARKER
            calls.append("srp")
            self.request_2fa_code()          # what _srp_authentication does

    fake = type(sys)("pyicloud")
    fake.PyiCloudService = FakeService
    monkeypatch.setitem(sys.modules, "pyicloud", fake)
    api = icloud_auth.PyiCloudBackend(APPLE_ID).start(MARKER, tmp_path, lambda: calls.append("need_code"))
    assert calls == ["srp", "need_code", "bridge"]
    assert api._password_raw is None


# ---------------------------------------------------------------- reload wrapper
def test_reload_swaps_session_before_next_request(tmp_path):
    import reminders_worker_reload as wrap

    live, incoming = tmp_path / "live", tmp_path / "incoming"
    live.mkdir(mode=0o700)
    (live / "u.session").write_text("old")

    class StubWorker:
        def __init__(self):
            self.service = "old-service"
            self.seen = []

        def call(self, op, args):
            self.seen.append((self.service, (live / "u.session").read_text()))
            if self.service is None:
                self.service = "new-service"
            return {"ok": True}

    w = StubWorker()
    line = json.dumps({"operation": "list_reminder_lists", "args": {}})
    assert wrap.handle(w, tmp_path, line) == {"result": {"ok": True}}
    assert w.seen[-1] == ("old-service", "old")
    incoming.mkdir(mode=0o700)
    (incoming / "u.session").write_text("new")
    (incoming / "u.cookiejar").write_text("jar")
    (incoming / "READY").write_text("")
    wrap.handle(w, tmp_path, line)
    assert w.seen[-1] == (None, "new")            # old service dropped before the call
    assert (live / "u.cookiejar").read_text() == "jar"
    assert not (incoming / "READY").exists()


def test_reload_rewrites_auth_hint(tmp_path):
    import reminders_worker as upstream
    import reminders_worker_reload as wrap

    class Expired:
        service = None

        def call(self, op, args):
            raise upstream.Failure("authentication_required", "Renew ... reminders_probe.py on the host.")

    (tmp_path / "live").mkdir()
    out = wrap.handle(Expired(), tmp_path, json.dumps({"operation": "list_reminder_lists", "args": {}}))
    assert out["error"]["code"] == "authentication_required"
    assert "icloud_login_start" in out["error"]["message"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
