package executor

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// healthDisplaySecrets supplies write-only probe inputs to the common redactor.
// Never include destinations alone: a diagnostic may legitimately name a host.
func (m *Manager) healthDisplaySecrets(ctx context.Context, s domain.Service) ([]string, error) {
	policy, _, err := m.healthPolicy(ctx, s)
	if err != nil {
		return nil, err
	}
	values := []string{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if x != "" {
				values = append(values, x)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		case map[string]any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	add := func(value string) {
		if value == "" {
			return
		}
		values = append(values, value)
		for _, line := range strings.Split(value, "\n") {
			if line != "" {
				values = append(values, line)
			}
		}
		var document any
		if json.Unmarshal([]byte(value), &document) == nil {
			walk(document)
		}
		if form, err := url.ParseQuery(value); err == nil {
			for _, items := range form {
				for _, item := range items {
					if item != "" {
						values = append(values, item)
					}
				}
			}
		}
	}
	addURL := func(raw string) {
		u, err := url.Parse(raw)
		if err == nil {
			for _, items := range u.Query() {
				for _, item := range items {
					add(item)
				}
			}
		}
	}
	for _, check := range policy.Checks {
		addURL(check.URL)
		add(check.BodyContains)
		for _, step := range append(append([]domain.HTTPStep{}, check.Steps...), check.CleanupSteps...) {
			addURL(step.URL)
			add(step.Body)
			add(step.BodyContains)
			for _, value := range step.Headers {
				add(value)
			}
		}
	}
	return values, nil
}
