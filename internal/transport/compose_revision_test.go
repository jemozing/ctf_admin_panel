package transport

import "testing"

func TestComposeRevisionRequestFlags(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		wantGit      bool
		wantConfirm  bool
		valid        bool
	}{
		{"Git preparation", `"action":"prepare_compose","compose_from_git":true`, true, false, true},
		{"workspace preparation", `"action":"prepare_compose"`, false, false, true},
		{"confirmed switch", `"action":"deploy","release_id":"release-new","confirm_compose_change":true`, false, true, true},
		{"confirmed rollback", `"action":"rollback","release_id":"release-old","confirm_compose_change":true`, false, true, true},
		{"Git on another action", `"action":"build","compose_from_git":true`, false, false, false},
		{"confirmation on another action", `"action":"prepare_compose","confirm_compose_change":true`, false, false, false},
		{"string confirmation", `"action":"deploy","release_id":"release-new","confirm_compose_change":"true"`, false, false, false},
		{"duplicate source", `"action":"prepare_compose","compose_from_git":true,"compose_from_git":false`, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req SubmitRequest
			err := decodeSubmit([]byte(`{"service_id":"service-test","idempotency_key":"reviewed",`+tc.fields+`}`), &req)
			if err == nil {
				err = req.Validate()
			}
			if (err == nil) != tc.valid {
				t.Fatalf("validation = %v", err)
			}
			if tc.valid && (req.ComposeFromGit != tc.wantGit || req.ConfirmComposeChange != tc.wantConfirm) {
				t.Fatalf("unexpected Compose revision flags: %+v", req)
			}
		})
	}
}
