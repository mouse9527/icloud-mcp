"""Offline tests for icloud_auth.py and reminders_worker_reload.py (no Apple account).

Run:  UPSTREAM_SCRIPTS=<icloud-mcp checkout>/scripts python3 -m pytest -q tests/
"""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
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


class FakeBackend:
    def __init__(self, need_code=False, good_code="123456", fail_login=False, finish_delay=0.0):
        self.need_code, self.good_code, self.fail_login, self.finish_delay = need_code, good_code, fail_login, finish_delay
        self.passwords = []

    def login(self, password, staging):
        self.passwords.append(password)
        if self.fail_login:
            raise RuntimeError("upstream said: bad password " + password)  # must not leak
        (staging / "userexamplecom.session").write_text(json.dumps({"session_token": "synthetic"}))
        (staging / "userexamplecom.cookiejar").write_text("#LWP-Cookies-2.0\n")
        return object()

    def needs_code(self, api):
        return self.need_code

    def validate_code(self, api, code):
        return code == self.good_code

    def finish(self, api):
        time.sleep(self.finish_delay)


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


@contextlib.contextmanager
def running(backend, tmp_path, clock=None):
    stderr = io.StringIO()
    old = sys.stderr
    sys.stderr = stderr
    (tmp_path / "live").mkdir(mode=0o700)
    svc = icloud_auth.AuthService("alice", "user@example.com", "https://icloud-auth.example:1443",
                                  tmp_path, backend, clock or time.time)
    web = icloud_auth.ThreadingHTTPServer(("127.0.0.1", 0), icloud_auth.make_web_handler(svc))
    mcp = icloud_auth.ThreadingHTTPServer(("127.0.0.1", 0), icloud_auth.make_mcp_handler(svc, {"icloud-mcp:8001"}))
    for s in (web, mcp):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        yield svc, web.server_address[1], mcp.server_address[1], stderr
    finally:
        web.shutdown()
        mcp.shutdown()
        sys.stderr = old


def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
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


def wait_state(svc, login_path, want, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        if svc.status()["last_result"] and svc.status()["last_result"]["result"] == want:
            return
        time.sleep(0.02)
    raise AssertionError(svc.status())


def test_everything_404_without_pending_token(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        for path in ["/", "/alice", "/alice/", "/alice/" + "x" * 43, "/bob/abc", "/healthz", "/../etc/passwd"]:
            assert req(wport, "GET", path)[0] == 404, path
            assert req(wport, "POST", path, "password=x")[0] == 404, path


def test_wrong_token_404_and_page_has_autofill_fields(tmp_path):
    with running(FakeBackend(), tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        assert req(wport, "GET", "/alice/wrong")[0] == 404
        assert req(wport, "GET", path.replace("/alice/", "/bob/"))[0] == 404
        page, cookie = open_link(wport, path)
        assert 'autocomplete="username"' in page and 'autocomplete="current-password"' in page
        assert 'value="user@example.com"' in page and "hidden" in page


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
    clock = Clock()
    with running(FakeBackend(), tmp_path, clock) as (svc, wport, mport, _):
        first = start_link(mport)
        second = start_link(mport)
        assert first != second
        assert req(wport, "GET", first)[0] == 404
        assert req(wport, "GET", second)[0] == 200


def test_full_login_one_time_and_no_password_leak(tmp_path):
    backend = FakeBackend(need_code=True)
    with running(backend, tmp_path) as (svc, wport, mport, stderr):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        status, page, _ = post(wport, path, cookie, username="user@example.com", password=MARKER)
        assert status == 200 and 'autocomplete="one-time-code"' in page
        assert backend.passwords == [MARKER]
        status, page, _ = post(wport, path, cookie, code="000000")
        assert "还可以再试" in page
        post(wport, path, cookie, code="123456")
        wait_state(svc, path, "ok")
        assert (tmp_path / "incoming" / "READY").exists()
        assert (tmp_path / "incoming" / "userexamplecom.session").exists()
        # single use: the same link (and the cookie) is now dead
        assert req(wport, "GET", path)[0] == 404
        assert post(wport, path, cookie, password=MARKER)[0] == 404
        _, status_reply = mcp_call(mport, "icloud_login_status")
        text = json.dumps(status_reply)
        assert path.rsplit("/", 1)[1] not in text and MARKER not in text
        logs = stderr.getvalue()
    assert MARKER not in logs and path.rsplit("/", 1)[1] not in logs
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert MARKER not in f.read_text(errors="ignore"), f


def test_failed_login_kills_token_and_hides_upstream_error(tmp_path):
    with running(FakeBackend(fail_login=True), tmp_path) as (svc, wport, mport, stderr):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        status, page, _ = post(wport, path, cookie, password=MARKER)
        assert status == 200 and "登录失败" in page and MARKER not in page
        assert req(wport, "GET", path)[0] == 404
        assert not (tmp_path / "incoming").exists()
        assert list((tmp_path / "staging").iterdir()) == []
        logs = stderr.getvalue()
    assert MARKER not in logs and "RuntimeError" in logs


def test_three_wrong_codes_fail(tmp_path):
    with running(FakeBackend(need_code=True), tmp_path) as (svc, wport, mport, _):
        path = start_link(mport)
        _, cookie = open_link(wport, path)
        post(wport, path, cookie, password=MARKER)
        for _ in range(3):
            post(wport, path, cookie, code="999999")
        assert req(wport, "GET", path)[0] == 404
        assert svc.status()["last_result"]["result"] == "failed"


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
