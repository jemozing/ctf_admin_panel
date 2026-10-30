#!/usr/bin/env python3
"""Read-only comparison of CyberBank immutable snapshots to pinned Git blobs."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
import subprocess

import sibir_bank_cycle as cycle


def git(*args):
    repo = cycle.ROOT / "tests/fixtures/vendor/2025-cybersibir-service-bank"
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)
    return result.stdout


def main():
    if git("rev-parse", "HEAD").decode().strip() != cycle.GIT_COMMIT:
        raise RuntimeError("Pinned local upstream commit mismatch")
    expected = {}
    dirs = set()
    for record in git("ls-tree", "-rz", cycle.GIT_COMMIT, "vuln-service").split(b"\x00"):
        if not record:
            continue
        metadata, filename = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        path = filename.decode()
        if path == "vuln-service/.env":
            continue
        if kind != "blob" or mode not in ("100644", "100755"):
            raise RuntimeError("Unexpected upstream object type")
        blob = git("cat-file", "blob", oid)
        expected[path] = {"path": path, "type": "file", "size": len(blob), "digest": "sha256:" + hashlib.sha256(blob).hexdigest(), "mode": int(mode[-3:], 8)}
        for parent in PurePosixPath(path).parents:
            if str(parent) != ".":
                dirs.add(str(parent))
    raw = cycle.Docker().helper(r'''
import json,sqlite3,sys
from pathlib import Path
db=Path(sys.argv[1])/'executor/executor.db'
connection=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
try:
    services=[json.loads(row[0]) for row in connection.execute('SELECT payload FROM services')]
    selected=[value for value in services if value.get('compose_project')=='ctfm-preview-sibir-bank']
    if len(selected)!=1:raise RuntimeError('Expected one registered CyberBank service')
    service=selected[0]
    snapshots=[json.loads(row[0]) for row in connection.execute("SELECT payload FROM records WHERE kind='snapshot' AND service_id=? ORDER BY created_at",(service['id'],))]
    print(json.dumps({'service_id':service['id'],'managed_paths':service['managed_paths'],'snapshots':snapshots}))
finally:connection.close()
''')
    metadata = json.loads(raw)
    assert metadata["managed_paths"] == [{"path": "vuln-service", "kind": "code", "exclusions": [".env"]}]
    baselines = [s for s in metadata["snapshots"] if s["purpose"] == "baseline" and s["state"] == "complete"]
    candidates = [s for s in metadata["snapshots"] if s["purpose"] == "candidate_source" and s["state"] == "complete" and s.get("git_source", {}).get("commit") == cycle.GIT_COMMIT]
    if len(baselines) != 1 or not candidates:
        raise RuntimeError("Complete baseline and exact Git candidate required")
    baseline, candidate = baselines[0], candidates[-1]
    before = {entry["path"]: entry for entry in baseline["manifest"]["entries"]}
    after = {entry["path"]: entry for entry in candidate["manifest"]["entries"]}
    actual_files = {name: entry for name, entry in after.items() if entry["type"] == "file"}
    assert set(actual_files) == set(expected), "Candidate file set differs from pinned Git excluding .env"
    for name, expected_entry in expected.items():
        assert all(actual_files[name].get(key) == value for key, value in expected_entry.items()), name
    assert {name for name, entry in after.items() if entry["type"] == "directory"} == dirs
    assert set(after) == set(expected) | dirs
    added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
    changes = []
    content = []
    metadata_only = []
    for name in sorted(set(before) & set(after)):
        old, new = before[name], after[name]
        fields = {key: {"baseline": old.get(key), "candidate": new.get(key)} for key in set(old) | set(new) if old.get(key) != new.get(key)}
        if fields:
            change = {"path": name, "fields": fields}
            changes.append(change)
            (content if set(fields) - {"uid", "gid", "mode"} else metadata_only).append(change)
    assert not added and not removed
    assert len(content) == 1 and content[0]["path"] == "vuln-service/front/public/index.html"
    required = [name for name in expected if name.startswith("vuln-service/cyberBank/src/db/")] + ["vuln-service/front/.nginx/nginx.conf"]
    assert len(required) == 9 and all(name in actual_files for name in required)
    report = {
        "test": "sibir-bank-immutable-manifest-to-pinned-git", "status": "passed", "observed_at": datetime.now(timezone.utc).isoformat(),
        "service_id": metadata["service_id"], "project": cycle.PROJECT, "repository": cycle.GIT_URL, "git_commit": cycle.GIT_COMMIT,
        "managed_paths": metadata["managed_paths"],
        "baseline": {key: baseline[key] for key in ("id", "purpose", "manifest_digest")},
        "candidate": {key: candidate[key] for key in ("id", "purpose", "manifest_digest", "git_source")},
        "counts": {"baseline_entries": len(before), "candidate_entries": len(after), "upstream_blob_files_verified": len(expected),
                   "modified_entries": len(changes), "metadata_only_modified_entries": len(metadata_only), "content_modified_entries": len(content),
                   "added_entries": len(added), "removed_entries": len(removed), "common_gid_changes": sum("gid" in change["fields"] for change in changes)},
        "assertions": {"all_selected_upstream_blob_hashes_sizes_modes_match": True, "file_set_and_directory_set_exact": True,
                       "all_eight_db_typescript_sources_and_nginx_template_present": True,
                       "only_content_delta_is_imported_local_baseline_html_marker": True,
                       "real_runtime_secrets_and_database_and_generated_images_absent_from_manifest": True},
        "excluded_public_upstream_file": "vuln-service/.env", "required_build_files_verified": required,
        "content_changes": content, "verified_files": list(expected.values()),
        "scope": "Read-only native SQLite snapshot metadata and local pinned Git objects. No registration, queue submission or runtime mutation.",
        "interpretation": "Imported local baseline marker to exact upstream commit, not a switch between two upstream revisions. Ownership metadata may also differ."
    }
    path = cycle.ROOT / "tests/integration/reports/sibir-bank-manifest-diff-2026-10-19.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "passed", "counts": report["counts"], "baseline": baseline["id"], "candidate": candidate["id"], "report": str(path)}))


if __name__ == "__main__":
    main()
