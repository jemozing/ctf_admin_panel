package config

import "fmt"

// SchedulerPolicy limits active jobs independently. Allocation, file copying,
// publication and the critical switching section retain a coarse artifact gate.
type SchedulerPolicy struct {
	Builds   uint32 `json:"builds,omitempty"`
	Copies   uint32 `json:"copies,omitempty"`
	Switches uint32 `json:"switches,omitempty"`
}

func (p SchedulerPolicy) Effective() SchedulerPolicy {
	if p.Builds == 0 {
		p.Builds = 1
	}
	if p.Copies == 0 {
		p.Copies = 1
	}
	if p.Switches == 0 {
		p.Switches = 1
	}
	return p
}
func (p SchedulerPolicy) Validate() error {
	p = p.Effective()
	if p.Builds > 4 || p.Copies > 4 || p.Switches > 4 {
		return fmt.Errorf("scheduler limits must be 1..4 per lane")
	}
	return nil
}
