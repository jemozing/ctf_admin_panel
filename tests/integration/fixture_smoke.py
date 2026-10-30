#!/usr/bin/env python3
"""Exercise only bundled fixtures; never accepts arbitrary Compose paths/projects."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PROFILES = {"named-volume": "named", "bind-mount": "bind", "writable-layer": "layer"}
sys.path.insert(0, str(FIXTURES))
from prepare import prepare_fixture  # noqa: E402


def run(arguments, *, environment=None, timeout=180):
    result = subprocess.run(arguments, env=environment, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(arguments)} failed:\n{result.stderr.strip()}\n{result.stdout.strip()}")
    return result.stdout.strip()


def api(url, method, path, value=None):
    body = None if value is None else json.dumps({"value": value}).encode()
    request = Request(url + path, data=body, method=method, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=3)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def wait_ready(compose, environment, timeout=60):
    deadline = time.monotonic() + timeout
    last_error = "no published port"
    while time.monotonic() < deadline:
        try:
            binding = run(compose + ["port", "app", "8080"], environment=environment, timeout=10)
            if not binding.startswith("127.0.0.1:") or "\n" in binding:
                raise RuntimeError(f"unexpected non-loopback binding: {binding}")
            url = "http://" + binding
            if api(url, "GET", "/health")[0] == 200:
                return url
        except (RuntimeError, OSError, URLError, ValueError) as error:
            last_error = str(error)
        time.sleep(0.25)
    raise RuntimeError(f"fixture did not become healthy: {last_error}")


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def exercise(profile, project, work, active):
    print(f"Checking fixture {profile} as {project}", file=sys.stderr)
    environment = os.environ.copy()
    environment.update({"CTFM_FIXTURE_UID": str(os.getuid()), "CTFM_FIXTURE_GID": str(os.getgid())})
    code = work / "code"
    data = work / "data"
    environment.update({"CTFM_FIXTURE_CODE_DIR": str(code), "CTFM_FIXTURE_DATA_DIR": str(data)})
    compose = ["docker", "compose", "--project-name", project, "--file", str(work / "compose.yaml")]
    config = json.loads(run(compose + ["config", "--format", "json"], environment=environment))
    require(config["name"].startswith("ctfm-fixture-"), "unsafe project name")
    for service in config["services"].values():
        context = Path(service["build"]["context"]).resolve()
        require(context.is_relative_to(work.resolve()), "build context must stay within fixture project")
        for port in service.get("ports", []):
            require(port.get("host_ip") == "127.0.0.1", "fixture port must be loopback only")
    active.append((compose, environment))
    run(compose + ["up", "--detach", "--build"], environment=environment, timeout=300)
    url = wait_ready(compose, environment)
    require(api(url, "GET", "/version")[1]["version"] == "v1", "unexpected baseline version")
    key = "smoke_" + uuid.uuid4().hex
    values = {"flags": "CTFM_TEST_FLAG_" + uuid.uuid4().hex, "state": "round:17"}
    for namespace, value in values.items():
        require(api(url, "PUT", f"/{namespace}/{key}", value)[0] == 200, "fixture write failed")
        require(api(url, "GET", f"/{namespace}/{key}")[1]["value"] == value, "fixture read failed")
    database_id = None
    if profile == "named-volume":
        database_id = run(compose + ["ps", "--quiet", "database"], environment=environment)
    if profile == "bind-mount":
        (code / "VERSION").write_text("v2\n")
        require(api(url, "GET", "/version")[1]["version"] == "v2", "bind code change was not observed")
        (code / "VERSION").write_text("v1\n")
    run(compose + ["up", "--detach", "--no-deps", "--force-recreate", "app"], environment=environment)
    url = wait_ready(compose, environment)
    expected_status = 404 if profile == "writable-layer" else 200
    for namespace, value in values.items():
        status, payload = api(url, "GET", f"/{namespace}/{key}")
        require(status == expected_status, f"unexpected {namespace} persistence after app recreation")
        if expected_status == 200:
            require(payload["value"] == value, "persistent value changed")
    if database_id is not None:
        require(run(compose + ["ps", "--quiet", "database"], environment=environment) == database_id,
                "recreating app also recreated its database")
        run(compose + ["up", "--detach", "--no-deps", "--force-recreate", "database"], environment=environment)
        url = wait_ready(compose, environment)
        for namespace, value in values.items():
            require(api(url, "GET", f"/{namespace}/{key}")[1]["value"] == value,
                    "named-volume data lost after database recreation")
    return {
        "profile": profile, "project": project, "status": "passed", "url": url,
        "assertion": "writable-layer data loss detected" if expected_status == 404 else "data survived recreation",
        "data_directory": str(data) if profile == "bind-mount" else None,
        "volume": project + "_database-data" if profile == "named-volume" else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=["all", *PROFILES], default="all")
    parser.add_argument("--keep", action="store_true", help="leave fixture containers running for inspection")
    parser.add_argument("--report", type=Path, help="save JSON report as well as printing it")
    args = parser.parse_args()
    active = []
    report = {"started_at": datetime.now(timezone.utc).isoformat(), "fixtures": [], "status": "failed"}
    # Keep bind data and code after teardown: data is never removed implicitly.
    work = Path(tempfile.mkdtemp(prefix="ctfm-fixture-"))
    report["work_directory"] = str(work)
    exit_code = 1
    try:
        report["compose"] = run(["docker", "compose", "version"])
        report["engine"] = json.loads(run(["docker", "version", "--format", "{{json .Server}}"], timeout=15))
        selected = list(PROFILES) if args.fixture == "all" else [args.fixture]
        suffix = uuid.uuid4().hex[:10]
        for profile in selected:
            project = f"ctfm-fixture-{PROFILES[profile]}-{suffix}"
            location = work / profile
            prepare_fixture(profile, location)
            report["fixtures"].append(exercise(profile, project, location, active))
        report["status"] = "passed"
        exit_code = 0
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    except KeyboardInterrupt:
        report["error"] = "interrupted"
        exit_code = 130
    finally:
        if not args.keep:
            cleanup_errors = []
            for compose, environment in reversed(active):
                try:
                    # Intentionally no --volumes, image prune, or host data deletion.
                    run(compose + ["down", "--remove-orphans"], environment=environment, timeout=60)
                except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                    cleanup_errors.append(str(error))
            if cleanup_errors:
                report["cleanup_errors"] = cleanup_errors
                report["status"] = "failed"
                exit_code = 1
        report["containers_kept"] = args.keep
        output = json.dumps(report, indent=2, ensure_ascii=False)
        print(output)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(output + "\n")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
