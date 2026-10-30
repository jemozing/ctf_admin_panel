#!/usr/bin/env python3
"""Read-only proof that every selected neuroLinks Git blob is in its snapshot."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import PurePosixPath
import subprocess

import sibir_neli234_cycle as cycle


def git(*args):
    repository=cycle.ROOT/"tests/fixtures/vendor/2025-cybersibir-service-neLi234"
    return subprocess.run(["git","-C",str(repository),*args],capture_output=True,check=True).stdout


def main():
    assert git("rev-parse","HEAD").decode().strip()==cycle.GIT_COMMIT
    expected={};directories=set()
    for record in git("ls-tree","-rz",cycle.GIT_COMMIT,"vuln-service").split(b"\0"):
        if not record:continue
        metadata,filename=record.split(b"\t",1);mode,kind,object_id=metadata.decode().split();name=filename.decode()
        if kind!="blob" or mode not in ("100644","100755"):raise RuntimeError("Unsupported upstream object")
        blob=git("cat-file","blob",object_id)
        expected[name]={"path":name,"type":"file","size":len(blob),"digest":"sha256:"+hashlib.sha256(blob).hexdigest(),"mode":int(mode[-3:],8)}
        directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent)!=".")
    metadata=json.loads(cycle.Docker().helper(r'''
import json,sqlite3,sys
from pathlib import Path
connection=sqlite3.connect('file:'+str(Path(sys.argv[1])/'executor/executor.db')+'?mode=ro',uri=True)
try:
    services=[json.loads(row[0]) for row in connection.execute('SELECT payload FROM services')]
    selected=[service for service in services if service.get('compose_project')=='ctfm-preview-sibir-neli234']
    if len(selected)!=1:raise RuntimeError('Expected one registered neuroLinks service')
    service=selected[0]
    snapshots=[json.loads(row[0]) for row in connection.execute("SELECT payload FROM records WHERE kind='snapshot' AND service_id=? ORDER BY created_at",(service['id'],))]
    print(json.dumps({'service_id':service['id'],'managed_paths':service['managed_paths'],'snapshots':snapshots}))
finally:connection.close()
'''))
    assert metadata["managed_paths"]==[{"path":"vuln-service","kind":"code"}]
    baselines=[s for s in metadata["snapshots"] if s["purpose"]=="baseline" and s["state"]=="complete"]
    candidates=[s for s in metadata["snapshots"] if s["purpose"]=="candidate_source" and s["state"]=="complete" and s.get("git_source",{}).get("commit")==cycle.GIT_COMMIT]
    if len(baselines)!=1 or not candidates:raise RuntimeError("Complete baseline and pinned Git candidate required")
    baseline,candidate=baselines[0],candidates[-1]
    before={e["path"]:e for e in baseline["manifest"]["entries"]};after={e["path"]:e for e in candidate["manifest"]["entries"]}
    actual={name:e for name,e in after.items() if e["type"]=="file"}
    assert set(actual)==set(expected)
    assert {name for name,e in after.items() if e["type"]=="directory"}==directories
    assert set(after)==set(expected)|directories
    for name,entry in expected.items():assert all(actual[name].get(key)==value for key,value in entry.items()),name
    added=sorted(set(after)-set(before));removed=sorted(set(before)-set(after));changes=[];content=[];metadata_only=[]
    for name in sorted(set(before)&set(after)):
        old,new=before[name],after[name]
        fields={key:{"baseline":old.get(key),"candidate":new.get(key)} for key in sorted(set(old)|set(new)) if old.get(key)!=new.get(key)}
        if fields:
            change={"path":name,"fields":fields};changes.append(change)
            (content if set(fields)-{"uid","gid","mode"} else metadata_only).append(change)
    assert not added and not removed
    assert len(content)==1 and content[0]["path"]=="vuln-service/controller/src/server.cpp"
    required=["vuln-service/controller/src/database_handler.cpp","vuln-service/controller/Dockerfile","vuln-service/controller/Makefile",
              "vuln-service/controller/sqlite/sqlite3.c","vuln-service/neurolink/Dockerfile","vuln-service/neurolink/neurolink"]
    assert all(name in actual for name in required)
    report={"test":"sibir-neli234-immutable-manifest-to-pinned-git","status":"passed","observed_at":datetime.now(timezone.utc).isoformat(),
        "service_id":metadata["service_id"],"project":cycle.PROJECT,"repository":cycle.GIT_URL,"git_commit":cycle.GIT_COMMIT,
        "managed_paths":metadata["managed_paths"],"baseline":{key:baseline[key] for key in ("id","purpose","manifest_digest")},
        "candidate":{key:candidate[key] for key in ("id","purpose","manifest_digest","git_source")},
        "counts":{"baseline_entries":len(before),"candidate_entries":len(after),"upstream_blob_files_verified":len(expected),
            "modified_entries":len(changes),"metadata_only_modified_entries":len(metadata_only),"content_modified_entries":len(content),
            "added_entries":len(added),"removed_entries":len(removed),"common_gid_changes":sum("gid" in c["fields"] for c in changes)},
        "assertions":{"all_selected_upstream_blob_hashes_sizes_modes_match":True,"file_and_directory_sets_exact":True,
            "real_cpp_sources_bundled_sqlite_and_opaque_binary_included":True,"only_content_delta_is_imported_controller_menu_marker":True,
            "runtime_sqlite_database_and_synthetic_user_credentials_absent_from_code_manifest":True},
        "required_build_files_verified":required,"content_changes":content,"verified_files":list(expected.values()),
        "scope":"Read-only native executor SQLite snapshot metadata and local pinned Git objects; no service operations submitted",
        "interpretation":"Imported local baseline to exact pinned Git commit, not two upstream revisions; ownership metadata may differ; opaque auxiliary binary is included but excluded from update targets"}
    path=cycle.ROOT/"tests/integration/reports/sibir-neli234-manifest-diff-2026-10-19.json"
    path.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"status":"passed","counts":report["counts"],"baseline":baseline["id"],"candidate":candidate["id"],"report":str(path)}))


if __name__=="__main__":main()
