#!/usr/bin/env python3
"""Validate observed neuroLinks browser cycle, including its safe failed Fetch."""
import hashlib
import json
from datetime import datetime, timezone

import sibir_neli234_cycle as cycle

LOCAL=cycle.LOCAL
REPORTS=cycle.ROOT/"tests/integration/reports"
SOURCE="vuln-service/controller/src/server.cpp"


def read(path):return json.loads(path.read_text())


def main():
    names=("baseline","built","deployed","rollback")
    phases={name:{kind:read(LOCAL/f"sibir-neli234-{name}-{kind}.json") for kind in ("panel","runtime","probe")} for name in names}
    base,built,deployed,rollback=(phases[name] for name in names)
    registered=read(LOCAL/"sibir-neli234-post-registration-runtime.json")
    preparation=read(LOCAL/"sibir-neli234-profile-preparation.json")
    failure={kind:read(LOCAL/f"sibir-neli234-first-fetch-failed-{kind}.json") for kind in ("panel","runtime","probe")}
    pre_new_data={kind:read(LOCAL/f"sibir-neli234-deployed-pre-new-data-{kind}.json") for kind in ("panel","runtime","probe")}
    new_data=read(LOCAL/"sibir-neli234-deployed-new-data.json")
    executor_update=read(LOCAL/"sibir-four-executor-update.json")
    assert executor_update["only_executor_recreated"] and executor_update["dashboard_and_all_game_containers_unchanged"]
    assert executor_update["limits"]=={"file_bytes_before":8388608,"file_bytes_after":16777216,"tree_bytes":33554432,"repository_bytes":67108864,"timeout_seconds":120}
    executor_images={phase:next(value for value in executor_update[phase] if value["name"]=="/ctfm-preview-executor-1") for phase in ("before","after")}
    final_executor=read(LOCAL/"sibir-neli234-final-executor.json")
    assert final_executor["image_id"]==executor_images["after"]["image_id"]
    assert final_executor["status"]=="running" and final_executor["health"]=="healthy"
    final_panel=rollback["panel"];service=final_panel["details"]["service"]
    assert service["managed_paths"]==[{"path":"vuln-service","kind":"code"}]
    assert service["targets"]==["controller"]
    baseline_release=base["panel"]["details"]["current_release_id"]
    releases={r["id"]:r for r in final_panel["details"]["releases"]}
    git_releases=[r for r in releases.values() if r["source"]=="git"]
    assert len(git_releases)==1
    git_release=git_releases[0]
    assert git_release["id"]!=baseline_release
    assert git_release["git_source"]["commit"]==cycle.GIT_COMMIT
    assert git_release["build_evidence_digest"]
    assert git_release["snapshot_id"]==final_panel["source"]["last_fetch"]["snapshot_id"]
    operations=final_panel["operations"]
    assert [o["spec"]["kind"] for o in operations]==["snapshot","fetch_source","fetch_source","build","deploy","rollback"]
    assert [o["state"] for o in operations]==["succeeded","failed","succeeded","succeeded","succeeded","succeeded"]
    assert all(o["outcome"]["actual_state_known"] and o["outcome"]["result_recorded"] for o in operations)
    failed=operations[1]
    assert failed["spec"]["id"]==failure["panel"]["operations"][-1]["spec"]["id"]
    assert failed["mutation_started"] is False
    assert failed["outcome"]["reason"]=="Git source byte limit exceeded"
    deploy_completed=datetime.fromisoformat(operations[-2]["updated_at"].replace("Z","+00:00"))
    new_data_recorded=datetime.fromisoformat(new_data["recorded_at"].replace("Z","+00:00"))
    rollback_created=datetime.fromisoformat(operations[-1]["created_at"].replace("Z","+00:00"))
    assert deploy_completed<new_data_recorded<rollback_created
    assert failure["panel"]["details"].get("candidate_id") is None
    assert failure["panel"]["details"]["current_release_id"]==baseline_release
    assert len(base["panel"]["operations"])==1
    assert len(built["panel"]["operations"])==4
    assert len(deployed["panel"]["operations"])==5
    assert [o["spec"]["id"] for o in deployed["panel"]["operations"]]==[o["spec"]["id"] for o in operations[:-1]]
    for evidence in (preparation,registered,failure["runtime"],built["runtime"]):
        for component in ("controller","neurolink"):
            for key in ("container_id","image_id","started_at"):
                assert evidence["containers"][component][key]==base["runtime"]["containers"][component][key]
        for key in ("volumes","source","sqlite_volume"):
            assert evidence[key]==base["runtime"][key]
    assert preparation["registered_service_mutated"] is False
    assert preparation["controller_read_only"] and preparation["auxiliary_container_preserved"] and preparation["auxiliary_started_at_preserved"]
    for key in ("fresh_login_successful","sqlite_thought_preserved","neurolink_concept_preserved"):
        assert failure["probe"][key]
    for key in ("thought_sha256","concept_sha256"):
        assert failure["probe"][key]==base["probe"][key]
        assert pre_new_data["probe"][key]==base["probe"][key]
    assert pre_new_data["runtime"]["sqlite_volume"]==new_data["before"]["sqlite_volume"]==base["runtime"]["sqlite_volume"]
    assert new_data["created_under_git_release"] and new_data["application_data_written_after_deploy"]
    assert new_data["dashboard_or_docker_service_operation_submitted"] is False and new_data["credentials_included"] is False
    assert new_data["before"]["baseline_marker_served"] is False
    assert new_data["before"]["source"]==new_data["after"]["source"]
    assert new_data["before"]["sqlite_volume"]["file_sha256"]!=new_data["after"]["sqlite_volume"]["file_sha256"]
    assert new_data["before"]["sqlite_volume"]["thoughts_count"]+1==new_data["after"]["sqlite_volume"]["thoughts_count"]
    for component in ("controller","neurolink"):
        for key in ("container_id","image_id","started_at"):
            assert pre_new_data["runtime"]["containers"][component][key]==new_data["before"]["containers"][component][key]==new_data["after"]["containers"][component][key]
    stable_files=("ctfm.runtime.yaml","vuln-service/controller/Dockerfile","vuln-service/neurolink/Dockerfile","vuln-service/neurolink/neurolink")
    release_ids={"baseline":baseline_release,"built":baseline_release,"deployed":git_release["id"],"rollback":baseline_release}
    for name,phase in phases.items():
        panel,runtime,probe=(phase[kind] for kind in ("panel","runtime","probe"))
        assert panel["details"]["current_release_id"]==release_ids[name]
        assert runtime["volumes"]==base["runtime"]["volumes"]
        expected_database=base["runtime"]["sqlite_volume"] if name in ("baseline","built") else new_data["after"]["sqlite_volume"]
        assert runtime["sqlite_volume"]==expected_database
        assert runtime["sqlite_volume"]["schema_sha256"]==base["runtime"]["sqlite_volume"]["schema_sha256"]
        assert runtime["sqlite_volume"]["integrity"]=="ok"
        assert runtime["sqlite_volume"]["users_count"]>=1 and runtime["sqlite_volume"]["thoughts_count"]>=1
        assert runtime["endpoint"]==probe["endpoint"]
        assert runtime["target_components"]==["controller"]
        assert runtime["data_preservation_scope"]["neurolink_recreation_allowed"] is False
        assert runtime["data_preservation_scope"]["neurolink_restart_durability_verified"] is False
        assert all(v["status"]=="running" and v["health"]=="healthy" for v in runtime["containers"].values())
        for key in ("container_id","image_id","started_at"):
            assert runtime["containers"]["neurolink"][key]==base["runtime"]["containers"]["neurolink"][key]
        assert runtime["containers"]["controller"]["read_only_rootfs"] is True
        assert runtime["containers"]["controller"]["working_dir"]=="/data"
        assert runtime["containers"]["controller"]["mounts"]==base["runtime"]["containers"]["controller"]["mounts"]
        assert all(probe[k] for k in ("fresh_login_successful","sqlite_thought_preserved","neurolink_concept_preserved"))
        for key in ("thought_sha256","concept_sha256"):
            assert probe[key]==base["probe"][key]
        if name in ("deployed","rollback"):
            assert probe["after_deploy_records_count"]==1 and probe["after_deploy_records_preserved"]
            assert probe["after_deploy_record_hashes"]==new_data["probe"]["after_deploy_record_hashes"]
        else:
            assert probe.get("after_deploy_records_count",0)==0
        for key in ("container_id","image_id","started_at"):
            assert probe[key]==runtime["containers"]["controller"][key]
            assert probe["neurolink_"+key]==runtime["containers"]["neurolink"][key]
        assert probe["data_created"] is False
        marker=name!="deployed"
        assert runtime["baseline_marker_served"]==runtime["source"]["baseline_marker_on_disk"]==probe["baseline_marker_present"]==marker
        for path in stable_files:assert runtime["source"]["files_sha256"][path]==base["runtime"]["source"]["files_sha256"][path]
        selected=releases[release_ids[name]]
        images={value["component"]:value["image_id"] for value in selected["images"]}
        assert set(images)==set(runtime["containers"])
        assert all(value["image_id"]==images[component] for component,value in runtime["containers"].items())
        observed={value["component"]:value for value in panel["details"]["containers"]}
        assert all(value["container_id"]==observed[component]["id"] for component,value in runtime["containers"].items())
    assert deployed["runtime"]["containers"]["controller"]["image_id"]!=base["runtime"]["containers"]["controller"]["image_id"]
    assert rollback["runtime"]["containers"]["controller"]["image_id"]==base["runtime"]["containers"]["controller"]["image_id"]
    assert len({phases[name]["runtime"]["containers"]["controller"]["container_id"] for name in ("baseline","deployed","rollback")})==3
    assert rollback["runtime"]["source"]["files_sha256"][SOURCE]==base["runtime"]["source"]["files_sha256"][SOURCE]
    comparison=read(REPORTS/"sibir-neli234-manifest-diff-2026-10-19.json")
    assert comparison["status"]=="passed" and all(comparison["assertions"].values())
    upstream_source=next(v for v in comparison["verified_files"] if v["path"]==SOURCE)
    assert deployed["runtime"]["source"]["files_sha256"][SOURCE]==upstream_source["digest"].removeprefix("sha256:")
    bundled_sqlite=next(v for v in comparison["verified_files"] if v["path"]=="vuln-service/controller/sqlite/sqlite3.c")
    assert bundled_sqlite["size"]==9235994 and (8<<20)<bundled_sqlite["size"]<(16<<20)
    screenshots=[]
    for path in sorted((REPORTS/"screenshots").glob("sibir-neli234-*.jpg")):
        screenshots.append({"path":str(path.relative_to(cycle.ROOT)),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
    for name in ("registration-confirm","git-connected","fetch-success","deploy-success","rollback-success","full-cycle"):
        assert (REPORTS/"screenshots"/f"sibir-neli234-{name}.jpg").is_file(),name
    summary=[]
    for operation in operations:
        start=datetime.fromisoformat(operation["created_at"].replace("Z","+00:00"));end=datetime.fromisoformat(operation["updated_at"].replace("Z","+00:00"))
        summary.append({"id":operation["spec"]["id"],"kind":operation["spec"]["kind"],"state":operation["state"],
            "duration_seconds":round((end-start).total_seconds(),3),"mutation_started":operation.get("mutation_started",False),
            "reason":operation.get("outcome",{}).get("reason"),"recovery_point_id":operation.get("recovery_point_id")})
    for name,phase in phases.items():
        if name!="rollback":phase["panel"].pop("events",None)
    report={"test":"sibir-neli234-browser-git-build-deploy-rollback","status":"passed","recorded_at":datetime.now(timezone.utc).isoformat(),
        "environment":{"platform":"macOS arm64 client, OrbStack Linux arm64 daemon; controller native arm64, opaque dependency amd64 emulation",
            "panel_url":"http://127.0.0.1:8765","compose_project":"ctfm-preview","executor":final_executor},
        "registration":{"method":"Actual browser wizard, immutable proposal review and Admin confirmation; helpers never submitted service operations",
            "proposal_id":"proposal-b544d656112273e8df0c3e07e67b5cfa","proposal_digest":"sha256:91bfd298b6de5df38241c795a9904c4bd41a66ee6a8aeb72248345508f55c884",
            "service_id":service["id"],"project_directory":cycle.SERVICE_DIRECTORY},
        "source":final_panel["source"],"baseline_release_id":baseline_release,"git_release_id":git_release["id"],
        "profile_adaptations":rollback["runtime"]["profile_differences"],"operations":summary,
        "assertions":{"successful_retry_then_real_build_deploy_rollback":True,"first_fetch_failed_safely_before_mutation":True,
            "registration_and_all_fetch_build_attempts_left_active_runtime_unchanged":True,"all_selected_upstream_blob_hashes_sizes_modes_match":True,
            "real_cpp_and_bundled_sqlite_and_opaque_binary_present":True,"deploy_changed_controller_image_and_removed_menu_marker":True,
            "rollback_restored_exact_baseline_controller_image_and_source":True,"auxiliary_container_image_started_at_unchanged":True,
            "sqlite_schema_integrity_and_named_volume_identity_preserved":True,"rollback_preserves_exact_database_after_new_deployed_gameplay_write":True,
            "fresh_login_reads_original_and_post_deploy_sqlite_thoughts_and_ram_concepts":True,
            "controller_read_only_root_and_frozen_profile_preserved":True,"rollback_submitted_no_new_fetch_or_build":True},
        "first_fetch_failure":{"cause":"Bundled sqlite3.c is 9,235,994 bytes, exceeding the former 8 MiB Git per-file bound",
            "bounded_fix":"Executor MaxFileBytes increased to 16 MiB; total selected tree remains 32 MiB and repository 64 MiB",
            "scope":"Only executor was updated between safe failure and browser retry; selected service source/runtime were unchanged",
            "executor_update":{"limits":executor_update["limits"],"only_executor_recreated":True,"dashboard_and_all_game_containers_unchanged":True,
                "executor_before_and_after":executor_images,"tests":executor_update["tests"]},
            "implementation_files":["internal/sourcegit/git.go","internal/sourcegit/git_test.go"],
            "evidence":failure},
        "before_registration_profile_preparation":preparation,"post_registration_runtime":registered,
        "deployed_before_new_game_data":pre_new_data,"new_game_data_created_under_git_release":new_data,
        "immutable_manifest_comparison":"tests/integration/reports/sibir-neli234-manifest-diff-2026-10-19.json",
        "phases":phases,"screenshots":screenshots,
        "limitations":["Imported local controller menu marker to exact pinned upstream commit, not two upstream revisions or a moving ref",
            "Only controller is a Build/Deploy/Rollback target; stateful opaque neurolink is excluded from recreation",
            "SQLite is durable in a named volume; opaque neurolink concepts survive this controller cycle in RAM, not a verified auxiliary restart",
            "Opaque binary source is unavailable; no general claim of complete internal-state audit is made",
            "Original Dockerfiles and database schema are unchanged; adapted Compose supplies working_dir=/data, limits and socket healthchecks",
            "Explicit platform/tmpfs were removed before registration because the current MVP rejects those runtime settings; controller root remains read-only",
            "Docker socket-listen healthchecks plus independent normal TCP registration/login/store/read probes passed; panel functional checker and organizer checker/exploits were not run",
            "Native arm64 controller and emulated amd64 auxiliary, not full native Linux amd64 platform acceptance; no private GitLab/offline/moving-ref test",
            "Loopback TCP port changes on controller recreation"],
        "final_state":{"service_running":True,"health":"healthy","current_release_id":baseline_release,"game_endpoint":rollback["runtime"]["endpoint"],
            "git_release_retained":git_release["id"],"auxiliary_recreated":False}}
    path=REPORTS/"sibir-neli234-web-cycle-2026-10-19.json"
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"status":"passed","operations":summary,"final_state":report["final_state"],"report":str(path)},ensure_ascii=False,indent=2))


if __name__=="__main__":main()
