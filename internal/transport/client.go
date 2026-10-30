package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type Client struct {
	http      *http.Client
	transport *http.Transport
}

// NewClient fixes all traffic to one configured Unix socket. Endpoint paths and
// redirects cannot cause TCP connections or select another host/socket.
func NewClient(socketPath string) (*Client, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, fmt.Errorf("socket path must be canonical and absolute")
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
	}, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second}
	return &Client{http: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport: transport}, nil
}

func (c *Client) Close() { c.transport.CloseIdleConnections() }

type ProtocolError struct {
	Status  int
	Code    string
	Message string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("executor protocol HTTP %d (%s): %s", e.Status, e.Code, e.Message)
}

type HealthResponse struct {
	Status        string `json:"status"`
	SchemaVersion int    `json:"schema_version"`
}

func (c *Client) Health(ctx context.Context) (HealthResponse, error) {
	var result HealthResponse
	err := c.request(ctx, http.MethodGet, "/v1/health", nil, &result)
	return result, err
}
func (c *Client) ListServices(ctx context.Context) ([]domain.Service, error) {
	var result []domain.Service
	err := c.request(ctx, http.MethodGet, "/v1/services", nil, &result)
	return result, err
}
func (c *Client) ListOperations(ctx context.Context) ([]domain.Operation, error) {
	var result []domain.Operation
	err := c.request(ctx, http.MethodGet, "/v1/operations", nil, &result)
	return result, err
}
func (c *Client) GetOperation(ctx context.Context, id domain.ID) (domain.Operation, error) {
	if err := id.Validate(); err != nil {
		return domain.Operation{}, err
	}
	var result domain.Operation
	err := c.request(ctx, http.MethodGet, "/v1/operations/"+string(id), nil, &result)
	return result, err
}
func (c *Client) Submit(ctx context.Context, request SubmitRequest) (domain.Operation, error) {
	if err := request.Validate(); err != nil {
		return domain.Operation{}, err
	}
	var result domain.Operation
	err := c.request(ctx, http.MethodPost, "/v1/operations", request, &result)
	return result, err
}

func (c *Client) request(ctx context.Context, method, path string, input, out any) error {
	return c.requestBounded(ctx, method, path, input, out, 8<<20)
}

func (c *Client) requestBounded(ctx context.Context, method, path string, input, out any, responseLimit int64) error {
	return c.requestLimits(ctx, method, path, input, out, MaxBodyBytes, responseLimit)
}

func (c *Client) requestLimits(ctx context.Context, method, path string, input, out any, bodyLimit, responseLimit int64) error {
	var body io.Reader
	if input != nil {
		payload, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if int64(len(payload)) > bodyLimit {
			return fmt.Errorf("executor request exceeds body limit")
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://executor"+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > responseLimit {
		return fmt.Errorf("executor response exceeds body limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var detail ErrorResponse
		if json.Unmarshal(data, &detail) != nil {
			detail = ErrorResponse{Code: "invalid_response", Message: "executor returned an invalid error response"}
		}
		return &ProtocolError{Status: response.StatusCode, Code: detail.Code, Message: detail.Message}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid executor response: %w", err)
	}
	return nil
}
