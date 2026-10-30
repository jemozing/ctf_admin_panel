#!/usr/bin/env python3
"""Validate and summarize the four saved browser cycles, without mutations."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "tests/integration/reports"
LOCAL = ROOT / "var/preview"
NAMES = {"bank": "CyberBank", "ncdex": "NightCity Data Exchange", "neli234": "neuroLinks 2-3-4", "eyesee": "EyeSee"}


def read(path):
    return json.loads(path.read_text())


def main():
    lock = {s["id"]: s for s in read(ROOT / "tests/real-services/services.lock.json")["services"]}
    final = read(LOCAL / "sibir-four-runtime-final.json")
    assert final["queue_idle"]
    actual = {(v["project"], v["component"]): v for v in final["containers"]}
    entries, all_operations = [], []
    for name, title in NAMES.items():
        path = REPORTS / f"sibir-{name}-web-cycle-2026-10-19.json"
        report = read(path)
        assert report["status"] == "passed" and report["assertions"] and all(v is True for v in report["assertions"].values())
        runtime = report["phases"]["rollback"]["runtime"]
        panel = report["phases"]["rollback"]["panel"]
        assert runtime["git_commit"] == lock[name]["commit"]
        assert runtime["git_url"] == lock[name]["repository"]
        assert panel["details"]["current_release_id"] == report["baseline_release_id"]
        assert panel["source"]["last_fetch"]["commit"] == lock[name]["commit"]
        assert report["git_release_id"] in [v["id"] for v in panel["details"]["releases"]]
        containers = runtime.get("containers", runtime.get("components"))
        for component, expected in containers.items():
            current = actual[(runtime["project"], component)]
            assert current["id"] == expected.get("container_id", expected.get("id"))
            assert current["image_id"] == expected["image_id"]
            assert current["started_at"] == expected["started_at"]
            assert current["state"] == "running" and current["health"] in (None, "healthy")
        for kind in ("fetch_source", "build", "deploy", "rollback"):
            passed = [v for v in report["operations"] if v["kind"] == kind and v["state"] == "succeeded"]
            assert len(passed) == 1
        assert len(report["operations"]) == (6 if name == "neli234" else 5)
        if name == "neli234":
            failures = [v for v in report["operations"] if v["state"] == "failed"]
            assert len(failures) == 1 and failures[0]["kind"] == "fetch_source"
        else:
            assert all(v["state"] == "succeeded" for v in report["operations"])
        image = REPORTS / "screenshots" / f"sibir-{name}-full-cycle.jpg"
        assert image.read_bytes()[:2] == b"\xff\xd8"
        entries.append({"id": name, "title": title, "status": "passed", "report": str(path.relative_to(ROOT)),
                        "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                        "service_id": panel["details"]["service"]["id"], "project": runtime["project"],
                        "git_url": runtime["git_url"], "commit": runtime["git_commit"],
                        "baseline_release_id": report["baseline_release_id"], "retained_git_release_id": report["git_release_id"],
                        "endpoint": runtime.get("url", runtime.get("endpoint", runtime.get("grpc_endpoint"))),
                        "operations": report["operations"], "checked_assertions": list(report["assertions"]),
                        "current_containers": [actual[(runtime["project"], c)] for c in containers],
                        "profile_adaptations": report["profile_adaptations"], "limitations": report["limitations"],
                        "screenshot": {"path": str(image.relative_to(ROOT)), "sha256": hashlib.sha256(image.read_bytes()).hexdigest()}})
        all_operations.extend(report["operations"])
    assert len(all_operations) == 21
    assert sum(v["state"] == "succeeded" for v in all_operations) == 20
    assert sum(v["kind"] in ("build", "deploy", "rollback") and v["state"] == "succeeded" for v in all_operations) == 12
    before = read(LOCAL / "sibir-four-unrelated-before.json")
    after = {v["name"]: v for v in read(LOCAL / "sibir-four-unrelated-after.json")}
    untouched = [v for v in before if v["project"] != "ctfm-preview-sibir-bioguard" and v["name"] != "/ctfm-preview-executor-1"]
    assert len(untouched) == 5 and all(after[v["name"]] == v for v in untouched)
    transition = read(LOCAL / "sibir-four-executor-update.json")
    assert transition["only_executor_recreated"] and transition["dashboard_and_all_game_containers_unchanged"]
    bio = read(LOCAL / "sibir-four-bioguard-observation.json")
    bio_probe = read(LOCAL / "sibir-four-bioguard-probe.json")
    assert bio_probe["patient_login_successful"] and bio_probe["diagnosis_preserved"]
    assert bio_probe["container_id"] == actual[("ctfm-preview-sibir-bioguard", "web")]["id"]
    limit_test = REPORTS / "git-bundled-source-limits-2026-10-19.json"
    assert read(limit_test)["status"] == "passed"
    overview = REPORTS / "screenshots/sibir-five-services-overview.jpg"
    assert overview.read_bytes()[:2] == b"\xff\xd8"
    result = {"test": "four-real-sibirctf-services-browser-git-build-deploy-rollback", "status": "passed",
              "recorded_at": datetime.now(timezone.utc).isoformat(), "panel_url": "http://127.0.0.1:8765",
              "scope": "Four additional real services; registration, Git setup, Fetch and every Build/Deploy/Rollback submitted through actual browser UI. Helpers only prepare owned isolated projects before registration, use normal application protocols and read evidence.",
              "services": entries,
              "counts": {"additional_services": 4, "sibir_services_in_panel_total": 5, "successful_build_deploy_rollback_operations": 12,
                         "successful_fetches": 4, "automatic_baseline_operations": 4, "historical_rejected_fetches": 1, "total_durable_records_in_four_cycles": 21},
              "git_limit_regression": {"report": str(limit_test.relative_to(ROOT)), "sha256": hashlib.sha256(limit_test.read_bytes()).hexdigest()},
              "executor_transition": transition, "final_queue_idle": True,
              "unrelated_preview": {"unchanged_original_containers": untouched,
                  "bioguard": {"note": "Separate Build and Rollback were observed for the pre-existing BioGuard during this session, outside the four-service browser sequence. Do not claim BioGuard was unchanged since the initial inventory; its current Git release is retained. The executor-only replacement later left every game container unchanged.",
                               "separate_operations": bio["operations"][-2:], "current_release_id": bio["details"]["current_release_id"], "functional_probe": bio_probe}},
              "overview_screenshot": {"path": str(overview.relative_to(ROOT)), "sha256": hashlib.sha256(overview.read_bytes()).hexdigest()},
              "limitations": ["Explicit adapted local Compose profiles; original upstream unsafe storage/runtime configurations remain rejected",
                              "One pinned upstream commit per service versus a documented locally marked imported baseline; not two upstream revisions or schema migration compatibility",
                              "Linux arm64 OrbStack; EyeSee supplied amd64 executable and opaque neurolink run through emulation; native Linux amd64 acceptance remains open",
                              "Functional preservation verified by independent normal HTTP/TCP/gRPC probes; panel readiness/functional URL checks are not configured and organizer checkers/exploits were not run",
                              "neuroLinks cycle targets controller only; opaque auxiliary RAM survives because it is not restarted, and restart durability is not claimed",
                              "One historical Git fetch refusal remains in the UI journal; bounded limit was fixed and retry succeeded, so not every historical attempt succeeded",
                              "No GitLab/private credentials, moved branch, daemon registry outage, complete fault matrix or reference-VM load acceptance in these cycles",
                              "Full MVP acceptance remains incomplete as documented in docs/progress.md"]}
    target = REPORTS / "sibir-four-web-cycles-2026-10-19.json"
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "counts": result["counts"], "report": str(target)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
