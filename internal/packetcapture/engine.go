package packetcapture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/packets"
)

type sourceWorker struct {
	source Source
	cancel context.CancelFunc
	iface  Interface
	failed atomic.Bool
}

type Engine struct {
	options         Options
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	applyMu         sync.Mutex
	mu              sync.Mutex
	policy          Policy
	digest          string
	workers         map[string]*sourceWorker
	queue           chan packets.Record
	epoch           string
	started         time.Time
	sequence        uint64
	counters        Counters
	lastError       string
	paused          bool
	pauseLeaseFloor time.Time
	tokens          float64
	refill          time.Time
}

func New(options Options) (*Engine, error) {
	if options.Sink == nil {
		return nil, errors.New("packet sink required")
	}
	if options.OpenSource == nil {
		options.OpenSource = openLiveSource
		if options.Mode != "" && options.Mode != "live" {
			return nil, errors.New("invalid live capture mode")
		}
		options.Mode = "live"
	} else if options.Mode == "" {
		options.Mode = "fixture"
	}
	if options.Interfaces == nil {
		options.Interfaces = ListInterfaces
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{options: options, ctx: ctx, cancel: cancel, workers: map[string]*sourceWorker{}, queue: make(chan packets.Record, QueueCapacity), epoch: hex.EncodeToString(random[:]), started: time.Now().UTC()}
	e.wg.Add(2)
	go e.writeLoop()
	go e.leaseLoop()
	return e, nil
}

func (e *Engine) Interfaces() ([]Interface, error) { return e.options.Interfaces() }

func (e *Engine) validateInterfaces(p Policy) (map[string]Interface, error) {
	result := map[string]Interface{}
	if !p.Enabled {
		return result, nil
	}
	available, err := e.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, wanted := range p.Interfaces {
		found := false
		for _, v := range available {
			if v.Name == wanted.Name && v.Index == wanted.Index {
				if !v.Up || !v.Supported {
					return nil, errors.New("capture interface must be up and Ethernet or loopback")
				}
				result[v.Name] = v
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("capture interface identity changed or is unavailable")
		}
	}
	return result, nil
}

// Preflight opens and closes receive-only sockets, but never reads a packet or
// changes the active policy. It proves current identity and raw-socket access.
func (e *Engine) Preflight(input Policy) error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	if e.ctx.Err() != nil {
		return errors.New("capture is closed")
	}
	p, err := NormalizePolicy(input)
	if err != nil {
		return err
	}
	available, err := e.validateInterfaces(p)
	if err != nil {
		return err
	}
	for _, v := range available {
		source, err := e.options.OpenSource(v)
		if err != nil {
			return errors.New("capture source unavailable; Linux CAP_NET_RAW and approved interface required")
		}
		_ = source.Close()
	}
	return nil
}

// Apply opens all newly needed sources before committing. A bad desired file,
// stale revision or unavailable source leaves the active policy unchanged.
func (e *Engine) Apply(input Policy) error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	fail := func(err error) error { e.mu.Lock(); e.lastError = err.Error(); e.mu.Unlock(); return err }
	if e.ctx.Err() != nil {
		return fail(errors.New("capture is closed"))
	}
	p, err := NormalizePolicy(input)
	if err != nil {
		return fail(err)
	}
	digest := PolicyDigest(p)
	e.mu.Lock()
	oldPolicy, oldDigest := e.policy, e.digest
	pauseFloor := e.pauseLeaseFloor
	old := make(map[string]*sourceWorker, len(e.workers))
	for k, v := range e.workers {
		old[k] = v
	}
	e.mu.Unlock()
	if p.Revision < oldPolicy.Revision || (p.Revision == oldPolicy.Revision && digest != oldDigest) {
		return fail(errors.New("capture policy revision must increase"))
	}
	if p.Enabled && !p.LeaseUntil.After(pauseFloor) {
		return fail(errors.New("capture requires a fresh runtime lease after pause"))
	}
	available, err := e.validateInterfaces(p)
	if err != nil {
		return fail(err)
	}
	next := map[string]*sourceWorker{}
	created := map[string]*sourceWorker{}
	for name, v := range available {
		if w := old[name]; w != nil && w.iface.Index == v.Index && !w.failed.Load() {
			next[name] = w
			continue
		}
		source, err := e.options.OpenSource(v)
		if err != nil {
			for _, w := range created {
				w.cancel()
				_ = w.source.Close()
			}
			return fail(errors.New("capture source unavailable; Linux CAP_NET_RAW and approved interface required"))
		}
		_, cancel := context.WithCancel(e.ctx)
		w := &sourceWorker{source: source, cancel: cancel, iface: v}
		next[name], created[name] = w, w
	}
	e.mu.Lock()
	e.policy, e.digest, e.workers, e.lastError, e.paused = p, digest, next, "", false
	e.tokens = float64(p.MaxPacketsPerSecond)
	e.refill = time.Now()
	e.mu.Unlock()
	var removed []*sourceWorker
	for name, w := range old {
		if next[name] != w {
			w.cancel()
			removed = append(removed, w)
		}
	}
	for _, w := range removed {
		_ = w.source.Close()
	}
	for _, w := range created {
		ctx, cancel := context.WithCancel(e.ctx)
		w.cancel = cancel
		e.wg.Add(1)
		go e.readLoop(ctx, w)
	}
	return nil
}

func (e *Engine) ReportPolicyFileError() {
	e.mu.Lock()
	e.lastError = "desired capture policy unavailable or invalid; active policy retained"
	e.mu.Unlock()
}

// Pause stops observation before a planned runtime mutation. A lease already
// published before this call cannot resume capture, even if its file is replayed.
func (e *Engine) Pause() error {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	if e.ctx.Err() != nil {
		return errors.New("capture is closed")
	}
	e.mu.Lock()
	if e.policy.LeaseUntil.After(e.pauseLeaseFloor) {
		e.pauseLeaseFloor = e.policy.LeaseUntil
	}
	e.policy.LeaseUntil = time.Now().UTC()
	e.paused = true
	e.lastError = "capture paused; fresh runtime verification and lease required"
	old := e.workers
	e.workers = map[string]*sourceWorker{}
	e.mu.Unlock()
	for _, w := range old {
		w.cancel()
	}
	for _, w := range old {
		_ = w.source.Close()
	}
	return nil
}

func (e *Engine) readLoop(ctx context.Context, w *sourceWorker) {
	defer e.wg.Done()
	for {
		frame, err := w.source.Read(ctx)
		if err != nil {
			if ctx.Err() == nil && e.ctx.Err() == nil {
				e.mu.Lock()
				if e.workers[w.iface.Name] == w {
					w.failed.Store(true)
					e.counters.SourceErrors++
					e.lastError = "capture source stopped; inspect interface and raw socket availability"
				}
				e.mu.Unlock()
			}
			return
		}
		e.observe(w, frame)
	}
}

func (e *Engine) observe(w *sourceWorker, frame Frame) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.policy.Enabled || !e.policy.LeaseUntil.After(time.Now()) || e.workers[w.iface.Name] != w {
		return
	}
	e.counters.Observed++
	if w.iface.Loopback && frame.PacketType == 4 {
		e.counters.DuplicateSuppressed++
		return
	}
	if len(frame.Data) > packets.MaxPacketBytes || len(frame.Data) == 0 || frame.WireLength < len(frame.Data) || frame.WireLength > 1<<20 {
		e.counters.Malformed++
		return
	}
	parsed, ok := parseEthernet(frame.Data)
	if !ok {
		e.counters.Unparsed++
		return
	}
	var iface InterfacePolicy
	for _, v := range e.policy.Interfaces {
		if v.Name == w.iface.Name {
			iface = v
			break
		}
	}
	matched := map[string]packets.Candidate{}
	ingress, egress := false, false
	for _, v := range iface.Endpoints {
		if v.Protocol != parsed.protocol {
			continue
		}
		source := v.Address == parsed.source.String() && v.Port == parsed.sourcePort
		destination := v.Address == parsed.destination.String() && v.Port == parsed.destinationPort
		if !source && !destination {
			continue
		}
		matched[v.ServiceID+"/"+v.Component] = packets.Candidate{ServiceID: v.ServiceID, Component: v.Component}
		ingress = ingress || destination
		egress = egress || source
	}
	if len(matched) == 0 {
		e.counters.Unmatched++
		return
	}
	e.counters.Matched++
	now := time.Now()
	e.tokens += now.Sub(e.refill).Seconds() * float64(e.policy.MaxPacketsPerSecond)
	e.refill = now
	if e.tokens > float64(e.policy.MaxPacketsPerSecond) {
		e.tokens = float64(e.policy.MaxPacketsPerSecond)
	}
	if e.tokens < 1 {
		e.counters.RateDropped++
		return
	}
	e.tokens--
	e.sequence++
	at := frame.At.UTC()
	if at.IsZero() {
		at = now.UTC()
	}
	record := packets.Record{Metadata: packets.Metadata{PacketID: fmt.Sprintf("%s-%d", e.epoch, e.sequence), CollectorEpoch: e.epoch, PolicyRevision: e.policy.Revision, At: at, Interface: w.iface.Name, IfIndex: w.iface.Index, Direction: "egress", Protocol: parsed.protocol, SourceIP: parsed.source.String(), DestinationIP: parsed.destination.String(), SourcePort: parsed.sourcePort, DestinationPort: parsed.destinationPort, TCPFlags: parsed.flags, WireLength: frame.WireLength, LinkType: 1, Attribution: "unique"}}
	if ingress {
		record.Direction = "ingress"
	}
	if ingress && egress {
		record.Direction = "ambiguous"
	}
	if len(matched) == 1 {
		for _, v := range matched {
			record.ServiceID, record.Component = v.ServiceID, v.Component
		}
	} else {
		record.Attribution = "ambiguous"
		for _, v := range matched {
			record.Candidates = append(record.Candidates, v)
		}
		sort.Slice(record.Candidates, func(i, j int) bool {
			a, b := record.Candidates[i], record.Candidates[j]
			return a.ServiceID+"/"+a.Component < b.ServiceID+"/"+b.Component
		})
	}
	bindings := map[packets.VersionBinding]bool{}
	for _, v := range iface.Endpoints {
		if v.Protocol == parsed.protocol && ((v.Address == parsed.source.String() && v.Port == parsed.sourcePort) || (v.Address == parsed.destination.String() && v.Port == parsed.destinationPort)) && (v.ReleaseID != "" || v.SourceDigest != "") {
			bindings[packets.VersionBinding{ServiceID: v.ServiceID, Component: v.Component, ReleaseID: v.ReleaseID, SourceDigest: v.SourceDigest}] = true
		}
	}
	for binding := range bindings {
		record.VersionBindings = append(record.VersionBindings, binding)
	}
	sort.Slice(record.VersionBindings, func(i, j int) bool {
		a, b := record.VersionBindings[i], record.VersionBindings[j]
		return a.ServiceID+"/"+a.Component+"/"+a.ReleaseID+"/"+a.SourceDigest < b.ServiceID+"/"+b.Component+"/"+b.ReleaseID+"/"+b.SourceDigest
	})
	if e.policy.Snaplen > 0 {
		n := min(len(frame.Data), e.policy.Snaplen)
		record.Data = append([]byte(nil), frame.Data[:n]...)
		record.CapturedLength = n
	} else {
		record.NotCapturedReason = "metadata_only"
	}
	record.Truncated = record.CapturedLength < record.WireLength
	select {
	case e.queue <- record:
		e.counters.Enqueued++
	default:
		e.counters.QueueDropped++
	}
}

func (e *Engine) writeLoop() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case record := <-e.queue:
			ok := e.options.Sink.Submit(record)
			e.mu.Lock()
			if ok {
				e.counters.Stored++
			} else {
				e.counters.SinkDropped++
			}
			e.mu.Unlock()
		}
	}
}

func (e *Engine) leaseLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.applyMu.Lock()
			e.mu.Lock()
			var expired []*sourceWorker
			if e.policy.Enabled && !e.policy.LeaseUntil.After(time.Now()) && len(e.workers) > 0 {
				for _, w := range e.workers {
					expired = append(expired, w)
				}
				e.workers = map[string]*sourceWorker{}
				e.lastError = "runtime capture lease expired; capture stopped"
			}
			e.mu.Unlock()
			for _, w := range expired {
				w.cancel()
			}
			for _, w := range expired {
				_ = w.source.Close()
			}
			e.applyMu.Unlock()
		}
	}
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	interfaces := make([]InterfacePolicy, len(e.policy.Interfaces))
	for n, v := range e.policy.Interfaces {
		interfaces[n] = v
		interfaces[n].Endpoints = append([]Endpoint(nil), v.Endpoints...)
	}
	available := e.ctx.Err() == nil
	for _, w := range e.workers {
		available = available && !w.failed.Load()
	}
	expired := e.policy.Enabled && !e.policy.LeaseUntil.After(time.Now())
	return Status{Available: available, Enabled: e.policy.Enabled, Running: e.policy.Enabled && !expired && len(e.workers) > 0 && available, Paused: e.paused, LeaseUntil: e.policy.LeaseUntil, LeaseExpired: expired, Mode: e.options.Mode, Epoch: e.epoch, StartedAt: e.started, Revision: e.policy.Revision, Digest: e.digest, Snaplen: e.policy.Snaplen, Interfaces: interfaces, QueueDepth: len(e.queue), QueueCapacity: QueueCapacity, Counters: e.counters, CountersScope: "collector_epoch", PreviousEpochCountersUnknown: true, KernelDropsKnown: false, Deduplication: "single_point_loopback_outgoing_suppressed", LastError: e.lastError}
}

func (e *Engine) Close(ctx context.Context) error {
	e.applyMu.Lock()
	e.cancel()
	e.mu.Lock()
	for _, w := range e.workers {
		w.cancel()
	}
	for _, w := range e.workers {
		_ = w.source.Close()
	}
	e.workers = map[string]*sourceWorker{}
	e.mu.Unlock()
	e.applyMu.Unlock()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
