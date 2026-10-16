#!/usr/bin/env python3
"""Upstream reminders_worker.py + hot session swap, without changing upstream.

icloud-auth never writes the live session directory. After a successful login it
renames a complete session into ``<root>/incoming`` and creates ``READY`` last.
Before each request this wrapper (single-threaded; the Go client serialises
calls) drops the in-memory PyiCloudService, so it can no longer rewrite the old
session files, then atomically moves the new files into ``<root>/live``.
"""
import argparse
import json
import logging
import os
from pathlib import Path
import sys

import reminders_worker as upstream

SESSION_SUFFIXES = (".session", ".cookiejar")
LOGIN_HINT = ("Apple login session missing or expired. Call icloud_login_start to get a "
              "one-time login link for the user, then retry after they finish.")


def adopt_incoming(root, worker):
    """Move a finished login from incoming/ into live/. Returns True if swapped."""
    incoming, live = root / "incoming", root / "live"
    ready = incoming / "READY"
    if not ready.exists():
        return False
    worker.service = None  # old PyiCloudService is unreachable -> never writes again
    for path in incoming.iterdir():
        if path.name.endswith(SESSION_SUFFIXES):
            os.replace(path, live / path.name)
    ready.unlink()
    return True


def handle(worker, root, line):
    try:
        adopt_incoming(root, worker)
        if len(line) > 65536:
            raise upstream.Failure("validation", "Request too large.")
        request = json.loads(line)
        return {"result": worker.call(request["operation"], request["args"])}
    except upstream.Failure as error:
        message = LOGIN_HINT if error.code == "authentication_required" else error.message
        return {"error": {"code": error.code, "message": message}}
    except Exception:
        worker.service = None
        return {"error": {"code": "reminders_error", "message": "Reminders request failed. "
                          "If the session expired call icloud_login_start; upstream details are withheld."}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--timezone", required=True)
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    live = Path(args.session_dir)
    if not live.is_dir() or live.stat().st_mode & 0o077:
        return 1
    root = live.parent
    worker = upstream.Worker(live, args.email, args.timezone)
    for line in sys.stdin:
        payload = json.dumps(handle(worker, root, line))
        if len(payload.encode()) > 1500000:
            payload = json.dumps({"error": {"code": "response_too_large", "message": "Use a smaller page size or one list."}})
        print(payload, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
