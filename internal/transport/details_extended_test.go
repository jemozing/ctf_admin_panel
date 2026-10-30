package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
	"github.com/ctf-service-manager/ctf-service-manager/internal/store"
)

type detailTestBackend struct {
	testBackend
	previews  int
	logs      int
	details   int
	events    int
	request   SubmitRequest
	component string
	tail      int
}

func (b *detailTestBackend) ServiceDetails(context.Context, domain.ID) (ServiceDetails, error) {
	b.details++
	return ServiceDetails{ObservedState: "running", Capabilities: map[string]bool{"prepare": true}}, nil
}
func (b *detailTestBackend) OperationEvents(context.Context, domain.ID) ([]store.Event, error) {
	b.events++
	return []store.Event{}, nil
}
func (b *detailTestBackend) Logs(_ context.Context, _ domain.ID, component string, tail int) (LogResult, error) {
	b.logs++
	b.component = component
	b.tail = tail
	return LogResult{Content: "fixture log", Truncated: true}, nil
}
func (b *detailTestBackend) Preview(_ context.Context, r SubmitRequest) (PreviewResult, error) {
	b.previews++
	b.request = r
	return PreviewResult{ServiceID: r.ServiceID, Action: r.Action, PlanDigest: domain.Hash([]byte("plan"))}, nil
}

func detailRequest(t *testing.T, b *detailTestBackend, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{options: Options{AllowedUIDs: []uint32{uint32(os.Geteuid())}, Backend: b}}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), principalKey{}, Principal{UID: uint32(os.Geteuid())}))
	response := httptest.NewRecorder()
	s.handle(response, req)
	return response
}
func TestDetailsEndpointsAndBoundedLogQueries(t *testing.T) {
	b := &detailTestBackend{}
	for _, target := range []string{"http://executor/v1/services/flags", "http://executor/v1/operations/op-1/events", "http://executor/v1/services/flags/logs?component=app&tail=500"} {
		response := detailRequest(t, b, "GET", target, "")
		if response.Code != 200 {
			t.Fatalf("%s: %d %s", target, response.Code, response.Body.String())
		}
	}
	if b.details != 1 || b.events != 1 || b.logs != 1 || b.component != "app" || b.tail != 500 {
		t.Fatalf("unexpected backend dispatch: %#v", b)
	}
	cases := []struct {
		method, target, body string
		code                 int
	}{
		{"POST", "http://executor/v1/services/flags", "{}", 405},
		{"GET", "http://executor/v1/services/flags/logs?component=app&tail=0", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?component=app&tail=501", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?component=app&tail=1&command=id", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?component=app&component=db&tail=1", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?component=app&tail=1&tail=2", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?component=app", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?tail=1", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?component=%zz&tail=1", "", 400},
		{"GET", "http://executor/v1/services/flags/logs?component=app&tail=1.5", "", 400},
		{"GET", "http://executor/v1/services/flags?path=/etc", "", 400},
		{"GET", "http://executor/v1/operations/op-1/events?after=1", "", 400},
		{"GET", "http://executor/v1/services/flags%2Flogs", "", 400},
		{"GET", "http://executor/v1/services/flags/unknown", "", 404},
		{"GET", "http://executor/v1/services/flags", "{}", 400},
	}
	for _, tc := range cases {
		response := detailRequest(t, b, tc.method, tc.target, tc.body)
		if response.Code != tc.code {
			t.Errorf("%s %s: status %d want %d", tc.method, tc.target, response.Code, tc.code)
		}
	}
	if b.details != 1 || b.events != 1 || b.logs != 1 {
		t.Fatal("invalid details request reached backend")
	}
}
func TestPreviewStrictlyDecodesExtendedSubmitFields(t *testing.T) {
	digest := domain.Hash([]byte("reviewed plan"))
	valid := SubmitRequest{ServiceID: "flags", Action: domain.OperationRollback, ReleaseID: "release-old", IdempotencyKey: "preview-key", Initiator: "defender", CandidateID: "candidate-1", PlanDigest: digest, ConfirmDataCompatibility: true}
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	b := &detailTestBackend{}
	response := detailRequest(t, b, "POST", "http://executor/v1/preview", string(encoded))
	if response.Code != 200 {
		t.Fatalf("valid preview: %d %s", response.Code, response.Body.String())
	}
	if !reflect.DeepEqual(valid, b.request) {
		t.Fatalf("extended request changed: %#v", b.request)
	}
	base := `"service_id":"flags","action":"deploy","release_id":"release-1"`
	cases := []string{
		`{` + base + `,"candidate_id":null}`,
		`{` + base + `,"candidate_id":["candidate-1"]}`,
		`{` + base + `,"candidate_id":"candidate-1","candidate_id":"candidate-2"}`,
		`{` + base + `,"candidate_id":"../source"}`,
		`{` + base + `,"initiator":false}`,
		`{` + base + `,"plan_digest":1}`,
		`{` + base + `,"plan_digest":"invalid"}`,
		`{` + base + `,"plan_digest":"` + string(digest) + `","plan_digest":"` + string(digest) + `"}`,
		`{` + base + `,"confirm_data_compatibility":"true"}`,
		`{` + base + `,"confirm_data_compatibility":null}`,
		`{` + base + `,"confirm_data_compatibility":1}`,
		`{` + base + `,"confirm_data_compatibility":true,"confirm_data_compatibility":false}`,
		`{` + base + `,"Confirm_Data_Compatibility":true}`,
		`{` + base + `,"path":"/var/run/docker.sock"}`,
		`{` + base + `} {}`,
	}
	for i, body := range cases {
		response := detailRequest(t, b, "POST", "http://executor/v1/preview", body)
		if response.Code != 400 {
			t.Errorf("invalid extended field case %d: %d %s", i, response.Code, response.Body.String())
		}
	}
	if b.previews != 1 {
		t.Fatal("invalid preview reached backend")
	}
	// Preview can omit an idempotency key; only this endpoint supplies a local
	// placeholder and it never submits a mutation.
	response = detailRequest(t, b, "POST", "http://executor/v1/preview", `{"service_id":"flags","action":"prepare"}`)
	if response.Code != 200 || b.request.IdempotencyKey != "preview" {
		t.Fatalf("default preview key: %d %#v", response.Code, b.request)
	}
}
func TestDecodeSubmitExtendedFieldsMatchJSONTypes(t *testing.T) {
	valid := `{"service_id":"flags","action":"deploy","release_id":"release-1","idempotency_key":"deploy-1","initiator":"defender","candidate_id":"candidate-1","plan_digest":"` + string(domain.Hash([]byte("plan"))) + `","confirm_data_compatibility":false}`
	var decoded SubmitRequest
	if err := decodeSubmit([]byte(valid), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.CandidateID != "candidate-1" || decoded.Initiator != "defender" || decoded.ConfirmDataCompatibility {
		t.Fatalf("incorrect extended values: %#v", decoded)
	}
	for _, body := range []string{`[]`, `null`, `{"confirm_data_compatibility":{}}`, `{"candidate_id":{}}`, `{"plan_digest":[]}`, valid + `null`} {
		if err := decodeSubmit([]byte(body), new(SubmitRequest)); err == nil {
			t.Fatalf("malformed extended request accepted: %s", body)
		}
	}
	// Error responses contain neither the rejected unknown-field value nor raw
	// payload bytes, even when the content was a credential.
	b := &detailTestBackend{}
	response := detailRequest(t, b, "POST", "http://executor/v1/preview", `{"password":"fixture-private-secret"}`)
	raw, _ := io.ReadAll(response.Result().Body)
	if strings.Contains(string(raw), "fixture-private-secret") {
		t.Fatal("rejected input value leaked")
	}
}
