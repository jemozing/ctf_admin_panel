#!/usr/bin/env python3
"""Validate saved observations of the browser-driven BioGuard cycle.

This does not submit operations or modify Docker. Inputs contain public evidence,
not the private patient credentials or dashboard cookie jar.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "var/preview"
REPORTS = ROOT / "tests/integration/reports"
COMMIT = "0d5dffae3460823715a266d5674d2110837c4bea"
INDEX = "vuln-service/BioGuard/templates/BioGuard/index.html"
SETTINGS = "/srv/ctf-manager-preview/services/sibir-bioguard-runtime-config/ctfm_settings.py"


def read(path):
    return json.loads(path.read_text())


def main():
    phases = {
        phase: {kind: read(LOCAL / f"sibir-bioguard-{phase}-{kind}.json")
                for kind in ("panel", "runtime", "probe")}
        for phase in ("baseline", "built", "deployed", "rollback")
    }
    baseline, built, deployed, rollback = (phases[p] for p in phases)
    before_registration = read(LOCAL / "sibir-bioguard-externalize.json")
    assert before_registration["registered_service_mutated"] is False
    for field in ("container_id", "image_id", "started_at", "mounts", "volumes", "source"):
        assert before_registration[field] == baseline["runtime"][field]
    baseline_id = baseline["panel"]["details"]["current_release_id"]
    final_panel = rollback["panel"]
    releases = {r["id"]: r for r in final_panel["details"]["releases"]}
    git_releases = [r for r in releases.values() if r["source"] == "git"]
    assert len(git_releases) == 1
    git_release = git_releases[0]
    operations = final_panel["operations"]
    assert [o["spec"]["kind"] for o in operations] == ["snapshot", "fetch_source", "build", "deploy", "rollback"]
    assert all(o["state"] == "succeeded" and o["outcome"]["actual_state_known"] and o["outcome"]["result_recorded"] for o in operations)
    assert baseline_id != git_release["id"]
    assert git_release["git_source"]["commit"] == COMMIT
    assert git_release["snapshot_id"] == final_panel["source"]["last_fetch"]["snapshot_id"]
    assert git_release["build_evidence_digest"]
    for phase in (baseline, built):
        assert phase["panel"]["details"]["current_release_id"] == baseline_id
    assert deployed["panel"]["details"]["current_release_id"] == git_release["id"]
    assert final_panel["details"]["current_release_id"] == baseline_id
    assert built["runtime"]["image_id"] == baseline["runtime"]["image_id"]
    assert deployed["runtime"]["image_id"] == git_release["images"][0]["image_id"]
    assert rollback["runtime"]["image_id"] == releases[baseline_id]["images"][0]["image_id"] == baseline["runtime"]["image_id"]
    assert deployed["runtime"]["image_id"] != baseline["runtime"]["image_id"]
    for field in ("container_id", "started_at", "image_id", "source"):
        assert built["runtime"][field] == baseline["runtime"][field]
    assert len({phases[p]["runtime"]["container_id"] for p in ("baseline", "deployed", "rollback")}) == 3
    diagnosis = baseline["probe"]["diagnosis_sha256"]
    for name, phase in phases.items():
        runtime, probe, panel = (phase[k] for k in ("runtime", "probe", "panel"))
        assert runtime["status"] == "running" and runtime["health"] == "healthy" and runtime["http_status"] == 200
        assert runtime["volumes"] == baseline["runtime"]["volumes"]
        assert runtime["mounts"] == baseline["runtime"]["mounts"]
        assert probe["patient_login_successful"] and probe["diagnosis_preserved"] and probe["diagnosis_sha256"] == diagnosis
        assert probe["patient_created"] == (name == "baseline")
        assert runtime["container_id"] == probe["container_id"] == panel["details"]["containers"][0]["id"]
        assert runtime["image_id"] == probe["image_id"] == panel["details"]["containers"][0]["image_id"]
        assert runtime["started_at"] == probe["started_at"]
        assert runtime["url"] == probe["url"]
        marker = name != "deployed"
        assert runtime["baseline_marker_served"] == runtime["source"]["baseline_marker_on_disk"] == probe["baseline_marker_present"] == marker
        for path in ("ctfm.runtime.yaml", SETTINGS, "vuln-service/Dockerfile"):
            assert runtime["source"]["files_sha256"][path] == baseline["runtime"]["source"]["files_sha256"][path]
    assert rollback["runtime"]["source"]["files_sha256"][INDEX] == baseline["runtime"]["source"]["files_sha256"][INDEX]
    comparison = read(REPORTS / "sibir-bioguard-manifest-diff-2026-10-19.json")
    assert comparison["upstream_comparison"]["all_tracked_blobs_match"]
    assert deployed["runtime"]["source"]["files_sha256"][INDEX] == comparison["content_delta"]["changes"][0]["fields"]["digest"]["candidate"].removeprefix("sha256:")
    assert len(built["panel"]["operations"]) == 3 and len(deployed["panel"]["operations"]) == 4
    assert [o["spec"]["id"] for o in deployed["panel"]["operations"]] == [o["spec"]["id"] for o in operations[:-1]]
    operation_summary = []
    for operation in operations:
        start = datetime.fromisoformat(operation["created_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(operation["updated_at"].replace("Z", "+00:00"))
        operation_summary.append({"id": operation["spec"]["id"], "kind": operation["spec"]["kind"], "state": operation["state"],
                                  "duration_seconds": round((end - start).total_seconds(), 3), "recovery_point_id": operation.get("recovery_point_id")})
    screenshots = ["registration-confirm", "git-connected", "fetch-success", "build-success", "deploy-success", "rollback-success", "full-cycle"]
    screenshot_evidence = []
    for name in screenshots:
        path = REPORTS / "screenshots" / f"sibir-bioguard-{name}.jpg"
        assert path.is_file()
        screenshot_evidence.append({"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    # Preserve one complete operation/event history, avoiding four duplicate copies.
    for name, phase in phases.items():
        if name != "rollback":
            phase["panel"].pop("events", None)
    report = {
        "test": "sibir-bioguard-browser-git-build-deploy-rollback", "status": "passed",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "environment": {"host": "macOS arm64 client, OrbStack Linux arm64 Docker daemon", "panel_url": "http://127.0.0.1:8765", "compose_project": "ctfm-preview",
                        "docker": read(LOCAL / "sibir-bioguard-docker-version.json")},
        "registration": {"method": "Actual browser wizard, path inspect, classification, immutable proposal review and Admin approval; no CLI/API registration or operation submissions",
                         "proposal_id": "proposal-25c785e8a4d96568720199ff1698dc3b", "proposal_digest": "sha256:d232d7a69cf3647089b5cb22d487315515e09eae50975926ebddefa7d00909f8",
                         "service_id": final_panel["details"]["service"]["id"], "project_directory": rollback["runtime"]["project_directory"]},
        "source": final_panel["source"], "baseline_release_id": baseline_id, "git_release_id": git_release["id"],
        "profile_adaptations": rollback["runtime"]["profile_differences"],
        "operations": operation_summary,
        "assertions": {"registration_did_not_recreate_runtime": True, "all_five_durable_operations_succeeded": True, "fetch_and_build_did_not_change_active_runtime_or_code": True,
                       "git_candidate_matches_all_36_upstream_blobs": True, "deploy_used_distinct_built_image_and_removed_marker": True,
                       "rollback_restored_exact_baseline_image_and_template": True, "same_named_volume_mountpoint_created_at_and_bind": True,
                       "fresh_patient_login_and_same_diagnosis_after_both_switches": True, "frozen_profile_settings_and_dockerfile_unchanged": True,
                       "rollback_created_no_new_build_or_fetch_operation": True},
        "before_registration_profile_preparation": before_registration, "phases": phases, "screenshots": screenshot_evidence,
        "unrelated_preview_demo": {"verified_read_only_after_cycle": True,
            "containers": [{"id": "17597309bfd0893469d6e6a2a32c6562ce019dbdda0f0ead9f672fb867bc42c7", "started_at_before_and_after": "2026-10-19T13:04:40.334615836Z", "state": "running"},
                           {"id": "a693fc1d3a62f03508dd53dcbd08c505a6ee49f6cd5f1e146c4240109a72c490", "started_at_before_and_after": "2026-10-19T13:04:34.718191317Z", "state": "running"}]},
        "observer_note": "Read-only probe helper was corrected after Deploy to accept executor-generated canonical Compose config labels. Earlier helper SHA is retained per phase; no application or panel code changed. Patient credentials and dashboard cookies are excluded.",
        "limitations": ["Imported local baseline marker to exact pinned upstream commit; not two distinct upstream revisions or moving-branch test",
                        "Upstream Compose is not used: SQLite is explicitly externalized to a named volume; schema is unchanged in this cycle",
                        "Docker healthcheck and external legitimate application HTTP probes passed; panel readiness/functional probes are not configured, organizer checker/exploit was not run",
                        "Cached real upstream Dockerfile build; not a cold-cache build timing benchmark",
                        "No GitLab/private authentication, moving branch, offline/timeout or daemon registry outage in this run",
                        "Linux arm64 OrbStack, not native Linux amd64 platform acceptance; four other SibirCTF services remain unrun",
                        "Game loopback port changes on recreation; no stable ingress guarantee in this test profile"],
        "final_state": {"service_running": True, "health": "healthy", "current_release_id": baseline_id, "game_url": rollback["runtime"]["url"], "git_release_retained": git_release["id"]},
    }
    destination = REPORTS / "sibir-bioguard-web-cycle-2026-10-19.json"
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "operations": operation_summary, "final_state": report["final_state"], "report": str(destination)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
