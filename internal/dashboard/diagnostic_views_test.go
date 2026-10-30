package dashboard

import (
	"testing"
)

func TestSensitiveViewsRejectViewerAndInvalidQueryBeforeExecutor(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "observer", RoleViewer)
	viewer, _, _ := loginAs(t, s, "observer")
	for _, path := range []string{"/api/services/game/files?comparison=workspace", "/api/services/game/log-records?component=*&tail=200", "/api/operations/op-1/diagnostics?after=0", "/api/stream?format=records&service_id=game&component=*"} {
		if r := request(t, s, "GET", path, nil, viewer, ""); r.Code != 403 {
			t.Fatalf("sensitive view %s returned %d: %s", path, r.Code, r.Body.String())
		}
	}
	for _, path := range []string{"/api/services/game/files?comparison=workspace&path=../.env", "/api/services/game/log-records?component=*&tail=501", "/api/services/game/log-records?include=%28", "/api/operations/op-1/diagnostics?after=-1", "/api/stream?format=records&service_id=game&component=*&command=id"} {
		if r := request(t, s, "GET", path, nil, admin, ""); r.Code != 400 {
			t.Fatalf("invalid view %s reached executor or bypassed validation: %d %s", path, r.Code, r.Body.String())
		}
	}
	for _, path := range []string{"/api/services/game/files", "/api/services/game/log-records", "/api/operations/op-1/diagnostics"} {
		if r := request(t, s, "POST", path, map[string]any{}, admin, csrf); r.Code != 405 {
			t.Fatalf("mutating method allowed %s: %d", path, r.Code)
		}
	}
}
