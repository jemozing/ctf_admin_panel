#!/usr/bin/env python3
"""Opt-in native installer/systemd lifecycle test on a fresh GitHub Actions VM.

This installs only CTF Manager's own files and units on an ephemeral runner.
Docker is queried by installer preflight; no game containers are created,
changed or stopped. Never run this script on a competition host.
"""

import argparse
import datetime as dt
import grp
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request


UNITS = ("ctfm-executor.service", "ctfm-dashboard.service")
BINARIES = ("ctf-manager", "ctfm-proxy", "ctfm-traffic", "ctfm-capture", "ctfm-packets")
CONFIG = Path("/etc/ctf-manager/executor.json")
STATE = Path("/var/lib/ctf-manager")
ORIGIN = "http://127.0.0.1:8765"


def command(arguments, **kwargs):
    return subprocess.run(list(map(str, arguments)), check=kwargs.pop("check", True), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=kwargs.pop("timeout", 45), **kwargs)


def fresh_runner(args):
    if not args.allow_system_install or sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64") or os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("requires an explicit opt-in on a fresh root Linux GitHub Actions runner")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("requires a running systemd system manager")
    protected = [Path("/etc/ctf-manager"), STATE, Path("/run/ctf-manager"), Path("/run/ctf-manager-host"),
                 Path("/srv/game-services"), Path("/srv/ctf-workspaces"),
                 Path("/etc/systemd/system/ctfm-executor.service.d")]
    protected += [Path("/usr/local/bin") / name for name in BINARIES]
    protected += [Path("/etc/systemd/system") / name for name in UNITS]
    if any(path.exists() or path.is_symlink() for path in protected):
        raise ValueError("native paths already exist; this runner is not fresh")
    for lookup, name in ((pwd.getpwnam, "ctfm-web"), (grp.getgrnam, "ctfm-ipc")):
        try:
            lookup(name)
        except KeyError:
            continue
        raise ValueError("native service identity already exists")
    for unit in UNITS:
        loaded = command(["systemctl", "show", unit, "--property=LoadState", "--value"], check=False).stdout.strip()
        if loaded != b"not-found":
            raise ValueError("a native unit is already loaded")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 8765))


def run(args):
    fresh_runner(args)
    report_path = Path(args.report).absolute()
    if report_path.exists() or report_path.is_symlink():
        raise ValueError("choose a new report path")
    package = Path(args.package_dir).resolve(strict=True)
    if not (package / "install.py").is_file():
        raise ValueError("the extracted native package is missing install.py")
    report = {"schema_version": 1, "recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope": {"ephemeral_github_actions_runner": True, "native_linux_amd64": True,
                        "real_systemd": True, "real_installer": True, "docker_queries": "read_only_preflight",
                        "game_containers_created": False, "user_vm_touched": False,
                        "credentials_or_raw_process_logs_retained": False}, "checks": [], "passed": False}
    owned = False
    phase = "install"
    csrf = ""
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def api(path, data=None):
        headers = {"Origin": ORIGIN, "Accept": "application/json"}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers.update({"Content-Type": "application/json", "X-CSRF-Token": csrf})
        request = urllib.request.Request(ORIGIN + path, data=body, headers=headers)
        try:
            response = opener.open(request, timeout=6)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            content = response.read(2 << 20)
            if "application/json" in response.headers.get("Content-Type", ""):
                content = json.loads(content)
            return response.status, content

    def wait_for(predicate, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, ValueError, urllib.error.URLError):
                pass
            time.sleep(0.25)
        raise AssertionError("native_service_readiness_timeout")

    def login(password):
        nonlocal csrf
        cookie_jar.clear()
        status, _ = api("/api/auth/login", {"username": "nativeadmin", "password": password})
        check("admin_login_" + phase, status == 200)
        status, session = api("/api/auth/session")
        check("admin_session_" + phase, status == 200 and session["user"]["role"] == "admin")
        csrf = session["csrf_token"]

    def service_pid(unit):
        return int(command(["systemctl", "show", unit, "--property=MainPID", "--value"]).stdout)

    def permissions(path, uid, gid, mode):
        info = path.stat()
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode)

    try:
        owned = True  # Fresh-runner checks passed; cleanup can touch only these new names.
        command([sys.executable, package / "install.py"], timeout=90)
        check("actual_native_installer", CONFIG.is_file() and (STATE / "install.json").is_file())
        release = json.loads((package / "release.json").read_text())
        actual_version = command(["/usr/local/bin/ctf-manager", "version"]).stdout.decode().strip()
        check("installed_binary_reports_package_version", actual_version == release["version"])
        web, ipc = pwd.getpwnam("ctfm-web"), grp.getgrnam("ctfm-ipc")
        check("web_identity_has_only_ipc_group", web.pw_uid != 0 and web.pw_gid == ipc.gr_gid and set(os.getgrouplist(web.pw_name, web.pw_gid)) == {ipc.gr_gid})
        check("private_state_ownership", permissions(STATE / "dashboard", web.pw_uid, ipc.gr_gid, 0o700) and permissions(STATE / "executor", 0, 0, 0o700) and permissions(CONFIG, 0, 0, 0o600))
        password = "Native-Smoke-" + secrets.token_hex(24)
        command(["runuser", "-u", "ctfm-web", "-g", "ctfm-ipc", "--", "/usr/local/bin/ctf-manager",
                 "init-admin", "--state", STATE / "dashboard", "--username", "nativeadmin"],
                input=(password + "\n").encode())
        check("administrator_created_through_unprivileged_cli", (STATE / "dashboard/dashboard.sqlite").is_file())
        command(["systemctl", "enable", "--now", *UNITS], timeout=90)
        wait_for(lambda: api("/healthz")[0] == 200)
        check("native_dashboard_health", True)
        login(password)
        wait_for(lambda: api("/api/status")[1].get("executor") == "ok")
        check("authenticated_native_peer_ipc", True)
        check("fresh_service_registry", api("/api/services") == (200, []))
        check("ipc_directory_and_socket_permissions", permissions(Path("/run/ctf-manager"), 0, ipc.gr_gid, 0o750) and permissions(Path("/run/ctf-manager/executor.sock"), 0, ipc.gr_gid, 0o660))
        dashboard_pid = service_pid("ctfm-dashboard.service")
        status = Path(f"/proc/{dashboard_pid}/status").read_text()
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        check("dashboard_actual_uid_and_no_capabilities", int(fields["Uid"].split()[0]) == web.pw_uid and int(fields["Gid"].split()[0]) == ipc.gr_gid and int(fields["CapEff"].strip(), 16) == 0)
        probe = """import socket
from pathlib import Path
for name in ('/etc/ctf-manager/executor.json','/var/lib/ctf-manager/executor/executor.db'):
 try:
  Path(name).open('rb').close()
 except PermissionError:
  continue
 raise SystemExit(1)
s=socket.socket(socket.AF_UNIX)
try:
 s.connect('/var/run/docker.sock')
except PermissionError:
 raise SystemExit(0)
raise SystemExit(1)
"""
        command(["runuser", "-u", "ctfm-web", "-g", "ctfm-ipc", "--", sys.executable, "-c", probe])
        check("web_identity_cannot_read_executor_config_or_open_docker", True)
        game = Path("/srv/game-services/native-demo")
        game.mkdir(mode=0o755)
        (game / "compose.yaml").write_text("services: {}\n")
        status, roots = api("/api/registration/directories", {"directory": ""})
        check("native_gui_lists_configured_root", status == 200 and any(entry["path"] == "/srv/game-services" for entry in roots["directories"]))
        status, listing = api("/api/registration/directories", {"directory": "/srv/game-services"})
        check("native_gui_lists_real_host_child", status == 200 and any(entry["path"] == str(game) for entry in listing["directories"]))
        status, listing = api("/api/registration/directories", {"directory": str(game)})
        check("native_gui_compose_hint_without_import", status == 200 and listing["compose_files"] == ["compose.yaml"] and api("/api/services") == (200, []))
        def valid_metrics():
            code, value = api("/api/metrics/host")
            latest = value.get("latest", {})
            return code == 200 and latest.get("source") == "approved_host_proc_files" and (latest.get("memory_total_bytes") or 0) > 0
        wait_for(valid_metrics, 60)
        check("native_host_metrics_have_verified_proc_evidence", True)
        phase = "executor_restart"
        command(["systemctl", "stop", "ctfm-executor.service"])
        check("dashboard_survives_executor_stop", api("/healthz")[0] == 200 and service_pid("ctfm-dashboard.service") == dashboard_pid and api("/api/status")[1].get("executor") == "unavailable")
        command(["systemctl", "start", "ctfm-executor.service"])
        wait_for(lambda: api("/api/status")[1].get("executor") == "ok")
        check("existing_dashboard_reconnects_after_executor_start", service_pid("ctfm-dashboard.service") == dashboard_pid)
        phase = "upgrade"
        command(["systemctl", "stop", "ctfm-dashboard.service", "ctfm-executor.service"])
        configuration = json.loads(CONFIG.read_text())
        configuration.setdefault("storage", {})["manual_snapshots"] = 4
        CONFIG.write_text(json.dumps(configuration, indent=2) + "\n")
        config_before = CONFIG.read_bytes()
        database = STATE / "dashboard/dashboard.sqlite"
        digest_before = hashlib.sha256(database.read_bytes()).hexdigest()
        command([sys.executable, package / "install.py", "--upgrade"], timeout=90)
        check("upgrade_preserves_config_and_dashboard_database", CONFIG.read_bytes() == config_before and hashlib.sha256(database.read_bytes()).hexdigest() == digest_before)
        command(["systemctl", "start", *UNITS], timeout=90)
        wait_for(lambda: api("/healthz")[0] == 200)
        login(password)
        wait_for(lambda: api("/api/status")[1].get("executor") == "ok")
        check("upgrade_preserves_administrator_and_working_native_services", True)
        report["passed"] = True
    except Exception as error:
        report.update(error_type=type(error).__name__, failed_phase=phase)
        if isinstance(error, subprocess.CalledProcessError):
            report["command_exit_code"] = error.returncode
            if len(error.cmd) > 1 and Path(str(error.cmd[1])).name == "install.py":
                diagnostic = (error.stderr or b"").decode("utf-8", errors="replace").splitlines()
                if diagnostic and diagnostic[0].startswith("native-install: "):
                report["installer_diagnostic"] = re.sub(r"(?<![A-Za-z0-9])/[^\s'\"]+", "<path>", diagnostic[0])[:512]
        report["unit_states"] = {}
        for unit in UNITS:
            try:
                result = command(["systemctl", "show", unit, "--property=ActiveState,SubState,Result,ExecMainStatus"], check=False)
                report["unit_states"][unit] = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
            except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
                report["unit_states"][unit] = {"query": "unavailable"}
    finally:
        if owned:
            try:
                stopped = command(["systemctl", "stop", "ctfm-dashboard.service", "ctfm-executor.service"], check=False, timeout=90)
                command(["systemctl", "disable", *UNITS], check=False, timeout=30)
                report["own_services_stopped"] = stopped.returncode == 0 and all(service_pid(unit) == 0 for unit in UNITS)
            except (OSError, ValueError, subprocess.SubprocessError):
                report["own_services_stopped"] = False
            if not report["own_services_stopped"]:
                report["passed"] = False
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "checks": len(report["checks"]), "own_services_stopped": report.get("own_services_stopped", False)}))
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--allow-system-install", action="store_true")
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("native-systemd-smoke: fresh ephemeral Linux GitHub Actions runner required", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
