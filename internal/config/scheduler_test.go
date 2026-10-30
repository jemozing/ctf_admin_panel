package config

import "testing"

func TestSchedulerIndependentBoundedDefaults(t *testing.T) {
	p := (SchedulerPolicy{}).Effective()
	if p.Builds != 1 || p.Copies != 1 || p.Switches != 1 {
		t.Fatal(p)
	}
	if err := (SchedulerPolicy{Builds: 4, Copies: 2, Switches: 1}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []SchedulerPolicy{{Builds: 5}, {Copies: 5}, {Switches: 5}} {
		if p.Validate() == nil {
			t.Fatal("unbounded scheduler accepted", p)
		}
	}
}
