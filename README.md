# icloud-mcp

An MCP server for **iCloud Calendar and Reminders**, packaged as one container
image, plus **icloud-auth**: a one-time-link login service so the Apple ID
password is never stored on the server.

It is a thin layer over [tomernation/icloud-mcp](https://github.com/tomernation/icloud-mcp)
(MIT), pinned at `c027fd74c3f1e8435313830b70adcc63bad898ca`. Upstream is not
forked; the Dockerfile clones that commit and applies three small patches.
Reminders use [timlaing/pyicloud](https://github.com/timlaing/pyicloud) at
`86c4bc90` (CloudKit web API; modern Reminders do not sync over CalDAV).

Image: `ghcr.io/mouse9527/icloud-mcp:sha-<commit>` (linux/amd64, no `latest`).

## What is in the image

| Path | What |
|---|---|
| `/icloud-mcp` | upstream Go server + `patches/` |
| `/opt/icloud/reminders_worker.py` | upstream Reminders worker, unmodified |
| `/opt/icloud/reminders_worker_reload.py` | wrapper: hot-swaps the Reminders session after a login, no restart |
| `/opt/icloud/icloud_auth.py` | login page + login MCP tools (stdlib + pyicloud) |
| `/opt/reminders/` | Python venv with pinned `pyicloud[cli]` (the `[cli]` extra is required; without `rich` pyicloud fails to import) |

No credentials, sessions or configuration are baked in. Every CI build exports
the image filesystem and fails if it finds session/cookie files, `.git`,
private keys in paths this project controls, or credential-like strings in the
build history / ENV. The audit report is kept as a workflow artifact.

## Patches

| Patch | Problem | Change |
|---|---|---|
| `0001-honor-https-proxy` | Upstream hard-codes `Proxy: nil`, so it cannot run where the only egress is an HTTP CONNECT proxy | Honor `HTTPS_PROXY`. TLS stays end to end and the host allowlist still checks every target |
| `0002-plain-http-mode` | Upstream HTTP mode requires in-process TLS 1.3 and RFC 7662 OAuth introspection; MCP clients such as Open WebUI cannot use it | `MCP_PLAIN_HTTP=true`: plain HTTP behind your own network controls, mandatory `Host` allowlist, optional static bearer, browser `Origin` refused. Write timeout raised to 150 s (Reminders calls may take 120 s) |
| `0003-china-mainland` | China mainland Apple IDs are served from `*.icloud.com.cn`; upstream allowlist rejects them | Allow `caldav.icloud.com.cn` / `pNNN-caldav.icloud.com.cn` (and contacts equivalents). `ICLOUD_CALDAV_BASE_URL` picks the entry point; only the two Apple URLs are accepted |

## Containers

Run the same image as two containers in one Pod sharing a private session
directory (e.g. an `emptyDir` mounted at `/session`, with `/session/live`
created `0700` by an init step).

### icloud-mcp (calendar + reminders)

```
args: ["-http", ":8080", "-audit-format", "json"]
```

| Env | Required | Notes |
|---|---|---|
| `MCP_PLAIN_HTTP` | yes | `true` |
| `MCP_ALLOWED_HOSTS` | yes | comma-separated `host:port` values exactly as clients send them in `Host` |
| `MCP_BEARER_TOKEN_FILE` | no | file with a static bearer token |
| `ICLOUD_EMAIL` / `ICLOUD_PASSWORD` | yes | Apple ID and an **app-specific password** (CalDAV). Long-lived; see limitations |
| `ICLOUD_CALDAV_BASE_URL` | no | `https://caldav.icloud.com` (default) or `https://caldav.icloud.com.cn` |
| `ICLOUD_CHINA` | China only | `1` — pyicloud uses `*.icloud.com.cn` |
| `ICLOUD_MCP_READ_ONLY` | no | upstream defaults hosted mode to read-only; set `false` for writes |
| `ICLOUD_MCP_DEFAULT_TZ` | recommended | IANA zone, e.g. `Asia/Shanghai` |
| `ICLOUD_MCP_ENABLE_REMINDERS` | yes | `true` |
| `ICLOUD_MCP_REMINDERS_SESSION_DIR` | yes | `/session/live` |
| `ICLOUD_MCP_REMINDERS_WORKER` | yes | `/opt/icloud/reminders_worker_reload.py` |
| `ICLOUD_MCP_REMINDERS_PYTHON` | yes | `/opt/reminders/bin/python` |
| `HTTPS_PROXY` / `NO_PROXY` | if needed | egress proxy |

`GET /healthz` (with an allowed `Host`) means the process is up and CalDAV
discovery succeeded at start, not that the Reminders session is valid.

### icloud-auth (link login)

```
command: ["/opt/reminders/bin/python", "/opt/icloud/icloud_auth.py"]
```

| Env | Required | Notes |
|---|---|---|
| `ICLOUD_AUTH_USER` | yes | path prefix, e.g. `alice` → links look like `<base>/alice/<token>` |
| `ICLOUD_APPLE_ID` | yes | account name only; placed in a hidden `username` field so password managers match |
| `ICLOUD_SESSION_ROOT` | yes | e.g. `/session` |
| `ICLOUD_AUTH_PUBLIC_BASE` | yes | public base URL of the login page (no trailing path) |
| `ICLOUD_AUTH_MCP_ALLOWED_HOSTS` | yes | `Host` allowlist for the MCP port |
| `ICLOUD_AUTH_WEB_PORT` / `ICLOUD_AUTH_MCP_PORT` | no | default `8000` / `8001` |
| `ICLOUD_CHINA` | China only | `1` |

Expose port 8000 (login page) to the user's browser through your ingress;
expose 8001 (MCP) only to the MCP client. The login port does not hold the
Apple ID app-specific password.

## Login flow

1. A Reminders tool returns `authentication_required` with the hint "call `icloud_login_start`".
2. The model calls `icloud_login_start` → `{url, expires_in_seconds: 300}`. A new link replaces any earlier one.
3. The user opens the link on their phone: password field (password manager fills it) → 6-digit code if asked → approve "allow iCloud data access" on a device if asked.
4. The session is written to `staging/`, renamed to `incoming/`, `READY` created last. Before its next request the Reminders wrapper drops the old in-memory client (so it can no longer rewrite the old files) and moves the new files into `live/`.
5. The model calls `icloud_login_status`, then retries. No restart.

Hardening: without a pending token every path on the login port is 404;
links are single-use and expire after 5 minutes; the first visit sets a
binding cookie (a leaked URL cannot be continued from another browser); one
password attempt per link; at most 3 code attempts; Python logging is disabled
and access logs mask the token; tool results never contain the token.

## Development

```
git clone https://github.com/tomernation/icloud-mcp.git /tmp/upstream
git -C /tmp/upstream checkout c027fd74c3f1e8435313830b70adcc63bad898ca
UPSTREAM_SCRIPTS=/tmp/upstream/scripts python -m pytest -q tests/    # offline, no Apple account
git -C /tmp/upstream apply "$PWD"/patches/*.patch && (cd /tmp/upstream && go vet ./... && go test ./...)
docker build --platform linux/amd64 .
```

## Known limitations

- **Two credentials.** Calendar uses CalDAV with an app-specific password: it does not expire and Apple cannot scope it, so it can also read iCloud Mail and Contacts. Revoke it at appleid.apple.com → App-Specific Passwords. Reminders use a pyicloud web session that expires; the Apple ID password itself is never stored.
- **China mainland**: supported via patch 0003 + `ICLOUD_CHINA=1`. pyicloud still sends `redirect_uri=https://www.icloud.com` during SRP in China mode (upstream behaviour); it works for the account it was tested with but is not guaranteed.
- **2FA trusted-device bridge** in pyicloud opens a direct WebSocket to Apple push servers (`17.0.0.0/8:443`) and ignores `HTTPS_PROXY`. Allow that egress if 2FA prompts are needed.
- **Opaque Reminders errors**: the worker deliberately withholds upstream error details, so an occasional `reminders_error` after login does not say why. Retrying usually works.
- Not supported: security-key (FIDO) accounts, legacy two-step verification, urgent alarms, location reminders, tags, attachments, editing lists. Date-only reminders get no timed alert.
- The session lives in the shared directory; recreating the Pod with an `emptyDir` means logging in again. Idempotency receipts are stored there too.
- One replica only: a session must be used by a single Reminders worker.

## License

MIT, see `LICENSE`. Upstream notices: `NOTICE.md`.
