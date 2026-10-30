package transport

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type metricTestBackend struct {
	detailTestBackend
	calls     int
	component string
	hostCalls int
}

func (b *metricTestBackend) Metrics(_ context.Context, id domain.ID) (MetricsResponse, error) {
	b.calls++
	return MetricsResponse{ServiceID: id}, nil
}
func (b *metricTestBackend) MetricsComponent(_ context.Context, id domain.ID, component string) (MetricsResponse, error) {
	b.calls++
	b.component = component
	return MetricsResponse{ServiceID: id, HistoryComponent: component}, nil
}
func (b *metricTestBackend) HostMetrics(context.Context) (HostMetricsResponse, error) {
	b.hostCalls++
	return HostMetricsResponse{RetentionSeconds: 3600}, nil
}

func TestMetricEndpointsOnlyAcceptFixedReadQueries(t *testing.T) {
	b := &metricTestBackend{}
	s := &Server{options: Options{AllowedUIDs: []uint32{uint32(os.Geteuid())}, Backend: b}}
	request := func(method, target string) int {
		r := httptest.NewRequest(method, "http://executor"+target, nil)
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, Principal{UID: uint32(os.Geteuid())}))
		w := httptest.NewRecorder()
		s.handle(w, r)
		return w.Code
	}
	for _, target := range []string{"/v1/metrics/host", "/v1/services/service/metrics", "/v1/services/service/metrics?component=app-1"} {
		if status := request("GET", target); status != 200 {
			t.Fatalf("%s status%d", target, status)
		}
	}
	if b.calls != 2 || b.component != "app-1" || b.hostCalls != 1 {
		t.Fatal("metric dispatch lost typed selector")
	}
	for _, target := range []string{"/v1/metrics/host?source=/proc", "/v1/services/service/metrics?component=app&component=db", "/v1/services/service/metrics?command=exec", "/v1/services/service/metrics?component=app&tail=5", "/v1/services/service/metrics?component=..%2Fapp", "/v1/services/service/metrics?component=", "/v1/services/service/metrics?component=%zz"} {
		if status := request("GET", target); status != 400 {
			t.Errorf("invalid query %s status%d", target, status)
		}
	}
	if status := request("POST", "/v1/metrics/host"); status != 405 {
		t.Fatal("host metric mutation accepted")
	}
	if b.calls != 2 || b.hostCalls != 1 {
		t.Fatal("invalid query reached collector")
	}
}
