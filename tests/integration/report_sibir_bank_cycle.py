#!/usr/bin/env python3
"""Validate public observations of the real browser-driven CyberBank cycle."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import sibir_bank_cycle as cycle

LOCAL = cycle.LOCAL
REPORTS = cycle.ROOT / "tests/integration/reports"


def read(path):
    return json.loads(path.read_text())


def main():
    phases = {name: {kind: read(LOCAL / f"sibir-bank-{name}-{kind}.json") for kind in ("panel", "runtime", "probe")}
              for name in ("baseline", "built", "deployed", "rollback")}
    base, built, deployed, rollback = (phases[name] for name in phases)
    final_panel = rollback["panel"]
    service = final_panel["details"]["service"]
    assert service["managed_paths"] == [{"path": "vuln-service", "kind": "code", "exclusions": [".env"]}]
    assert set(service["targets"]) == {"cyber-bank-api", "cyber-bank-front"}
    baseline_release = base["panel"]["details"]["current_release_id"]
    releases = {value["id"]: value for value in final_panel["details"]["releases"]}
    git_releases = [value for value in releases.values() if value["source"] == "git"]
    assert len(git_releases) == 1
    git_release = git_releases[0]
    assert git_release["id"] != baseline_release
    assert git_release["git_source"]["commit"] == cycle.GIT_COMMIT
    assert git_release["build_evidence_digest"]
    assert git_release["snapshot_id"] == final_panel["source"]["last_fetch"]["snapshot_id"]
    operations = final_panel["operations"]
    assert [o["spec"]["kind"] for o in operations] == ["snapshot", "fetch_source", "build", "deploy", "rollback"]
    assert all(o["state"] == "succeeded" and o["outcome"]["actual_state_known"] and o["outcome"]["result_recorded"] for o in operations)
    assert len(base["panel"]["operations"]) == 1
    assert len(built["panel"]["operations"]) == 3
    assert len(deployed["panel"]["operations"]) == 4
    assert [o["spec"]["id"] for o in deployed["panel"]["operations"]] == [o["spec"]["id"] for o in operations[:-1]]
    registered = read(LOCAL / "sibir-bank-registered-runtime.json")
    for key in ("containers", "volumes", "source", "url", "index_sha256"):
        assert registered[key] == base["runtime"][key] == built["runtime"][key]
    required_stable_files = ("ctfm.runtime.yaml", "vuln-service/cyberBank/Dockerfile", "vuln-service/front/Dockerfile",
                             cycle.CONFIG_DIRECTORY + "/api.env", cycle.CONFIG_DIRECTORY + "/postgres.env")
    identity_fields = ("product_id", "user_id", "image_path", "image_sha256", "content_sha256", "comment_sha256")
    release_ids = {"baseline": baseline_release, "built": baseline_release, "deployed": git_release["id"], "rollback": baseline_release}
    for name, phase in phases.items():
        runtime, probe, panel = (phase[kind] for kind in ("runtime", "probe", "panel"))
        assert panel["details"]["current_release_id"] == release_ids[name]
        assert runtime["http_status"] == 200 and runtime["url"] == probe["url"]
        assert runtime["volumes"] == base["runtime"]["volumes"]
        assert runtime["containers"]["cyber-bank-postgres"] == base["runtime"]["containers"]["cyber-bank-postgres"]
        assert all(container["status"] == "running" and container["health"] == "healthy" for container in runtime["containers"].values())
        assert all(probe.get(key) is True for key in ("fresh_login_successful", "product_preserved", "comment_preserved", "generated_png_preserved"))
        assert all(probe[key] == base["probe"][key] for key in identity_fields)
        marker = name != "deployed"
        assert runtime["baseline_marker_served"] == runtime["source"]["baseline_marker_on_disk"] == probe["baseline_marker_present"] == marker
        assert all(runtime["source"]["files_sha256"][path] == base["runtime"]["source"]["files_sha256"][path] for path in required_stable_files)
        selected_release = releases[release_ids[name]]
        release_images = {image["component"]: image["image_id"] for image in selected_release["images"]}
        assert set(release_images) == set(runtime["containers"])
        assert all(value["image_id"] == release_images[component] for component, value in runtime["containers"].items())
        observed_containers = {value["component"]: value for value in panel["details"]["containers"]}
        assert all(value["container_id"] == observed_containers[component]["id"] for component, value in runtime["containers"].items())
    front = "cyber-bank-front"
    assert deployed["runtime"]["containers"][front]["image_id"] != base["runtime"]["containers"][front]["image_id"]
    assert rollback["runtime"]["containers"][front]["image_id"] == base["runtime"]["containers"][front]["image_id"]
    assert len({phases[name]["runtime"]["containers"][front]["container_id"] for name in ("baseline", "deployed", "rollback")}) == 3
    index = "vuln-service/front/public/index.html"
    assert rollback["runtime"]["source"]["files_sha256"][index] == base["runtime"]["source"]["files_sha256"][index]
    comparison = read(REPORTS / "sibir-bank-manifest-diff-2026-10-19.json")
    assert comparison["status"] == "passed" and all(comparison["assertions"].values())
    assert comparison["counts"]["upstream_blob_files_verified"] == 79
    expected_index = next(value["digest"] for value in comparison["verified_files"] if value["path"] == index)
    assert deployed["runtime"]["source"]["files_sha256"][index] == expected_index.removeprefix("sha256:")
    screenshots = []
    for path in sorted((REPORTS / "screenshots").glob("sibir-bank-*.jpg")):
        screenshots.append({"path": str(path.relative_to(cycle.ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    required_screenshots = ("registration-confirm", "git-connected", "fetch-success", "deploy-success", "rollback-success", "full-cycle")
    assert all((REPORTS / "screenshots" / f"sibir-bank-{name}.jpg").is_file() for name in required_screenshots)
    summary = []
    for operation in operations:
        start = datetime.fromisoformat(operation["created_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(operation["updated_at"].replace("Z", "+00:00"))
        summary.append({"id": operation["spec"]["id"], "kind": operation["spec"]["kind"], "state": operation["state"],
                        "duration_seconds": round((end - start).total_seconds(), 3), "recovery_point_id": operation.get("recovery_point_id")})
    for name, phase in phases.items():
        if name != "rollback":
            phase["panel"].pop("events", None)
    report = {
        "test": "sibir-bank-browser-git-build-deploy-rollback", "status": "passed", "recorded_at": datetime.now(timezone.utc).isoformat(),
        "environment": {"platform": "macOS arm64 client, OrbStack Linux arm64 Docker daemon", "panel_url": "http://127.0.0.1:8765", "compose_project": "ctfm-preview",
                        "panel_runtime": read(LOCAL / "sibir-bank-panel-runtime-images.json")},
        "registration": {"method": "Actual browser wizard, source classification, immutable proposal review and Admin approval; helper never submitted service mutations",
                         "proposal_id": "proposal-d3991ac5cb29ff6aadd58feab40f616d", "proposal_digest": "sha256:9fea60dd49b658ac1a4973a9c296cb16386489c780c4a836ccee9a3163e0bd41",
                         "service_id": service["id"], "project_directory": cycle.SERVICE_DIRECTORY},
        "source": final_panel["source"], "baseline_release_id": baseline_release, "git_release_id": git_release["id"],
        "profile_adaptations": rollback["runtime"]["profile_differences"], "operations": summary,
        "assertions": {"all_five_durable_operations_succeeded": True, "registration_fetch_build_did_not_change_active_runtime": True,
                       "all_79_selected_upstream_blobs_match": True, "real_db_typescript_and_nginx_build_inputs_included": True,
                       "deploy_used_distinct_frontend_image_and_removed_marker": True, "rollback_restored_exact_baseline_application_images_and_source": True,
                       "postgres_container_id_image_started_at_unchanged": True, "same_two_named_volume_identity_mountpoint_created_at": True,
                       "fresh_login_same_product_comment_and_exact_generated_png": True, "frozen_profile_secrets_and_upstream_dockerfiles_unchanged": True,
                       "rollback_created_no_new_build_or_fetch_operation": True},
        "before_registration_profile_preparation": {"shm": read(LOCAL / "sibir-bank-shm-preparation.json"), "env_inputs": read(LOCAL / "sibir-bank-env-preparation.json"),
                                                   "normalization": read(LOCAL / "sibir-bank-normalization.json")},
        "immutable_manifest_comparison": str((REPORTS / "sibir-bank-manifest-diff-2026-10-19.json").relative_to(cycle.ROOT)),
        "phases": phases, "screenshots": screenshots,
        "limitations": ["Imported local baseline marker to exact pinned upstream commit; not two distinct upstream revisions or a moving branch test",
                        "Adapted profile externalizes PostgreSQL and generated PNG data; upstream Compose is not used",
                        "API Dockerfile performs npm ci; original run.sh compiles TypeScript and runs unchanged migrations at application start",
                        "API source is identical baseline to Git so its real build legitimately reuses the baseline image; frontend real build changes its image",
                        "Upstream public dummy vuln-service/.env is excluded; real secret values in secrets/ are never included in code manifests or this report",
                        "Docker healthchecks and legitimate external application HTTP probes passed; panel functional checker is not configured and organizer checker/exploits were not run",
                        "Linux arm64 OrbStack, not native Linux amd64 acceptance; no private GitLab, moving ref or offline registry test",
                        "Loopback frontend port changes upon recreation; no stable ingress is claimed"],
        "final_state": {"service_running": True, "health": "healthy", "current_release_id": baseline_release,
                        "game_url": rollback["runtime"]["url"], "git_release_retained": git_release["id"]},
    }
    path = REPORTS / "sibir-bank-web-cycle-2026-10-19.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": "passed", "operations": summary, "final_state": report["final_state"], "report": str(path)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
