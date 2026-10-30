package dashboard

import "testing"

func TestCancellationRequiresRoleCSRFAndBoundedServerIdentity(t *testing.T) {
	s, _ := testServer(t)
	admin, csrf, _ := loginAs(t, s, "admin")
	createAccount(t, s, admin, csrf, "reader", RoleViewer)
	viewer, vcsrf, _ := loginAs(t, s, "reader")
	for _, item := range []struct {
		name   string
		csrf   string
		viewer bool
		body   any
		want   int
	}{
		{"csrf", "", false, map[string]any{}, 403},
		{"viewer", vcsrf, true, map[string]any{}, 403},
		{"actor spoof", csrf, false, map[string]any{"actor": "someone"}, 400},
		{"typed request", csrf, false, map[string]any{}, 404},
	} {
		t.Run(item.name, func(t *testing.T) {
			cookie := admin
			if item.viewer {
				cookie = viewer
			}
			v := request(t, s, "POST", "/api/operations/op-a/cancel", item.body, cookie, item.csrf)
			if v.Code != item.want {
				t.Fatalf("%d: %s", v.Code, v.Body)
			}
		})
	}
}
