#!/usr/bin/env python3
"""Save read-only panel evidence; never submit registration or service actions."""
import argparse
from datetime import datetime, timezone
import http.cookiejar
import json
import os
from pathlib import Path
import stat
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def private_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise RuntimeError("Private regular 0600 file required")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--access", type=Path, default=ROOT / "var/preview/access.json")
    parser.add_argument("--cookies", type=Path, default=ROOT / "var/preview/observer.cookies")
    args = parser.parse_args()
    private_file(args.access)
    access = json.loads(args.access.read_text())
    base = access["url"].rstrip("/")
    address = urllib.parse.urlsplit(base)
    if address.scheme != "http" or address.hostname != "127.0.0.1" or address.path:
        raise RuntimeError("Observer is restricted to the local loopback panel")
    cookies = http.cookiejar.LWPCookieJar(str(args.cookies))
    if args.cookies.exists():
        private_file(args.cookies)
        cookies.load(ignore_discard=True, ignore_expires=True)
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

    def get(path):
        with opener.open(base + path, timeout=30) as response:
            return json.loads(response.read())

    try:
        get("/api/auth/session")
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        login = urllib.request.Request(base + "/api/auth/login", data=json.dumps({"username": access["username"], "password": access["password"]}).encode(), headers={"Content-Type": "application/json", "Origin": base})
        with opener.open(login, timeout=30) as response:
            response.read()
        if not args.cookies.exists():
            descriptor = os.open(args.cookies, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        cookies.save(ignore_discard=True, ignore_expires=True)
    services = [value for value in get("/api/services") if value["compose_project"] == args.project]
    if len(services) != 1:
        raise RuntimeError("Expected exactly one service for this Compose project")
    service_id = services[0]["id"]
    operations = [value for value in get("/api/operations") if value["spec"]["service_id"] == service_id]
    evidence = {"at": datetime.now(timezone.utc).isoformat(), "project": args.project,
                "details": get("/api/services/" + service_id), "source": get("/api/services/" + service_id + "/source"),
                "operations": operations, "events": {value["spec"]["id"]: get("/api/operations/" + value["spec"]["id"] + "/events") for value in operations},
                "observer_scope": "Only authentication and GET requests; service mutations performed separately in browser"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"service_id": service_id, "current_release_id": evidence["details"].get("current_release_id"), "candidate_id": evidence["details"].get("candidate_id"), "operations": [{"id": value["spec"]["id"], "kind": value["spec"]["kind"], "state": value["state"]} for value in operations]}))


if __name__ == "__main__":
    main()
