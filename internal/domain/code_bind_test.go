package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func codeBindFixture() Service {
	s := serviceFixture()
	s.DataPaths = append(s.DataPaths, DataPath{Name: "project-code", Kind: StorageBind, Source: s.ProjectDirectory, Target: "/app", Component: "app", LossAccepted: true, AllowCodeUpdates: true})
	return s
}

func TestCodeBindRequiresScopedDisposableConsent(t *testing.T) {
	if err := codeBindFixture().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Service){
		"no code permission":    func(s *Service) { s.DataPaths[1].AllowCodeUpdates = false },
		"loss unacknowledged":   func(s *Service) { s.DataPaths[1].LossAccepted = false },
		"significant data":      func(s *Service) { s.DataPaths[1].Significant = true },
		"volume cannot opt in":  func(s *Service) { s.DataPaths[1].Kind = StorageNamedVolume; s.DataPaths[1].Source = "code-volume" },
		"parent of project":     func(s *Service) { s.DataPaths[1].Source = "/srv/ctf" },
		"prefix sibling":        func(s *Service) { s.DataPaths[1].Source = s.ProjectDirectory + "-sibling" },
		"workspace":             func(s *Service) { s.DataPaths[1].Source = s.SourceDirectory },
		"component not stopped": func(s *Service) { s.DataPaths[1].Component = "db" },
	} {
		t.Run(name, func(t *testing.T) {
			s := codeBindFixture()
			change(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("unsafe code-bind policy accepted")
			}
		})
	}
	s := codeBindFixture()
	s.DataPaths[1].Source += "/app"
	if err := s.Validate(); err != nil {
		t.Fatalf("exact managed subdirectory bind rejected: %v", err)
	}
}

func TestCodeBindConsentCannotCoverAnotherConsumersStorage(t *testing.T) {
	s := codeBindFixture()
	s.DataPaths = append(s.DataPaths, DataPath{Name: "other-consumer", Kind: StorageBind, Source: s.ProjectDirectory, Target: "/consumer", Component: "db", Significant: true})
	if err := s.Validate(); err == nil {
		t.Fatal("one consumer's consent waived another consumer's preserved storage")
	}
	s.DataPaths[2].Significant = false
	s.DataPaths[2].LossAccepted = true
	s.DataPaths[2].AllowCodeUpdates = true
	if err := s.Validate(); err == nil {
		t.Fatal("shared consumer omitted from targets")
	}
	s.Targets = append(s.Targets, "db")
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCodeBindConsentIsStoredAndOldPolicyDefaultsRemainStrict(t *testing.T) {
	s := codeBindFixture()
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Service
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.Validate() != nil || !decoded.DataPaths[1].AllowCodeUpdates {
		t.Fatalf("consent not preserved in policy: %v", err)
	}
	legacy := strings.Replace(string(encoded), `,"allow_code_updates":true`, "", 1)
	decoded = Service{}
	if err := json.Unmarshal([]byte(legacy), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Validate() == nil {
		t.Fatal("old overlap silently became an approved code bind")
	}
}
