package transport

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

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

func TestComposeDraftRequestRejectsAmbiguousOrOutOfScopeInput(t *testing.T) {
	revision := "sha256:" + strings.Repeat("a", 64)
	draft := `{"content":"services: {}","revision":"` + revision + `"}`
	for _, tc := range []struct {
		name, action, fields string
		valid                bool
	}{
		{"editor", "prepare_compose", `"compose_draft":` + draft, true},
		{"Git plus editor", "prepare_compose", `"compose_from_git":true,"compose_draft":` + draft, false},
		{"another operation", "build", `"compose_draft":` + draft, false},
		{"null", "prepare_compose", `"compose_draft":null`, false},
		{"caller-supplied filename", "prepare_compose", `"compose_draft":{"path":".env","content":"test","revision":"` + revision + `"}`, false},
		{"duplicate nested field", "prepare_compose", `"compose_draft":{"content":"first","content":"last","revision":"` + revision + `"}`, false},
		{"invalid revision", "prepare_compose", `"compose_draft":{"content":"test","revision":"latest"}`, false},
		{"too large", "prepare_compose", `"compose_draft":` + string(mustJSONComposeDraft(t, ComposeDraft{Content: strings.Repeat("A", MaxComposeDraftBytes+1), Revision: domain.Digest(revision)})), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req SubmitRequest
			err := decodeSubmit([]byte(`{"service_id":"service-test","idempotency_key":"reviewed","action":"`+tc.action+`",`+tc.fields+`}`), &req)
			if err == nil {
				err = req.Validate()
			}
			if (err == nil) != tc.valid {
				t.Fatalf("validation = %v", err)
			}
			if tc.valid && (req.ComposeDraft == nil || req.ComposeDraft.Content != "services: {}" || string(req.ComposeDraft.Revision) != revision) {
				t.Fatal("editor input was lost or changed")
			}
		})
	}
}

func mustJSONComposeDraft(t *testing.T, draft ComposeDraft) []byte {
	t.Helper()
	data, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
