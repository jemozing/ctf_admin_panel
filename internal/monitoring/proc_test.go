package monitoring

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/config"
	"github.com/ctf-service-manager/ctf-service-manager/internal/transport"
)

func cpuFixture(user, idle string) string {
	return "cpu " + user + " 0 0 " + idle + " 10 0 0 0 5 0\ncpu0 0 0 0 0\ncpu1 0 0 0 0\n"
}

func TestProcCPUExcludesGuestAndRejectsInvalidCounters(t *testing.T) {
	v, err := parseCPU(cpuFixture("100", "200"))
	if err != nil || v.total != 310 || v.idle != 210 || v.cores != 2 {
		t.Fatalf("CPU totals incl guest twice: %+v %v", v, err)
	}
	for _, raw := range []string{"cpu 1 2 3\n", strings.Replace(cpuFixture("100", "200"), "100", "-1", 1), cpuFixture("18446744073709551615", "1"), "cpu 1 0 0 1\n"} {
		if _, err := parseCPU(raw); err == nil {
			t.Fatalf("invalid CPU accepted %q", raw)
		}
	}
}

func TestProcMemoryLoadUptimeAndNetwork(t *testing.T) {
	memory := "MemTotal: 8192 kB\nMemAvailable: 2048 kB\nSwapTotal: 1024 kB\nSwapFree: 512 kB\n"
	v, err := parseMemory(memory)
	if err != nil || v["MemTotal:"] != 8192*1024 {
		t.Fatalf("memory: %v %v", v, err)
	}
	for _, raw := range []string{strings.Replace(memory, "2048", "99999", 1), strings.Replace(memory, "kB", "MB", 1), strings.Replace(memory, "MemAvailable: 2048 kB\n", "", 1), memory + "SwapFree: 1 kB\n"} {
		if _, err := parseMemory(raw); err == nil {
			t.Fatal("invalid memory accepted")
		}
	}
	load, err := parseLoad("0.00 0.10 1.25 1/423 933\n")
	if err != nil || load[2] != 1.25 {
		t.Fatal("load values changed")
	}
	if _, err := parseLoad("NaN 1 2 1/2 33"); err == nil {
		t.Fatal("nonfinite load accepted")
	}
	if v, err := parseUptime("123.45 345.67\n"); err != nil || v != 123.45 {
		t.Fatal("uptime changed")
	}
	if _, err := parseUptime("Inf 1"); err == nil {
		t.Fatal("infinite uptime accepted")
	}
	net := "Inter-| Receive | Transmit\n eth0: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0\n lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n"
	interfaces, rx, tx, err := parseNetwork(net)
	if err != nil || len(interfaces) != 2 || rx != 100 || tx != 200 {
		t.Fatalf("network loopback counted: %v %d %d %v", interfaces, rx, tx, err)
	}
	if _, _, _, err := parseNetwork(strings.Replace(net, "100", "-1", 1)); err == nil {
		t.Fatal("negative network accepted")
	}
	if _, err := add(math.MaxUint64, 1); err == nil {
		t.Fatal("counter wrap accepted")
	}
}

func TestHostCPURequiresAdjacentEvidenceAndHandlesReboot(t *testing.T) {
	s := HostSampler{}
	at := time.Unix(1000, 0)
	apply := func(at time.Time, user, idle, uptime string) transport.HostMetricsSample {
		r := transport.HostMetricsSample{Errors: map[string]string{}}
		s.applySources(&r, map[string]string{"stat": cpuFixture(user, idle), "uptime": uptime + " 1"}, at)
		return r
	}
	first := apply(at, "100", "200", "100")
	if first.CPUPercent != nil {
		t.Fatal("first CPU fabricated")
	}
	second := apply(at.Add(5*time.Second), "150", "250", "105")
	if second.CPUPercent == nil || *second.CPUPercent != 50 {
		t.Fatalf("CPU percentage: %v", second.CPUPercent)
	}
	gap := apply(at.Add(time.Minute), "200", "300", "160")
	if gap.CPUPercent != nil {
		t.Fatal("CPU bridged missing observations")
	}
	reboot := apply(at.Add(65*time.Second), "1", "2", "5")
	if reboot.CPUPercent != nil {
		t.Fatal("reboot counter reset became CPU spike")
	}
	s.applySources(&transport.HostMetricsSample{Errors: map[string]string{}}, map[string]string{}, at.Add(70*time.Second))
	next := apply(at.Add(75*time.Second), "100", "100", "15")
	if next.CPUPercent != nil {
		t.Fatal("missing source did not reset delta")
	}
}

func TestHostMountEvidenceIsExactReadOnlyProcAndPID1Net(t *testing.T) {
	line := func(root, target, options, fs string) string {
		return "321 20 0:30 " + root + " " + HostDirectory + "/" + target + " " + options + " - " + fs + " proc rw,nosuid\n"
	}
	good := line("/stat", "stat", "ro,nosuid", "proc") + line("/1/net/dev//deleted", "net-dev", "ro", "proc")
	verified := verifiedProcMounts(good)
	if !verified["stat"] || !verified["net-dev"] {
		t.Fatal("real exact host mounts rejected")
	}
	for _, raw := range []string{line("/stat", "stat", "rw", "proc"), line("/stat", "stat", "ro", "ext4"), line("/self/net/dev", "net-dev", "ro", "proc"), line("/2/net/dev", "net-dev", "ro", "proc"), line("/stat/wrong", "stat", "ro", "proc"), line("/stat", "stat-other", "ro", "proc")} {
		if len(verifiedProcMounts(raw)) > 0 {
			t.Fatalf("unapproved mount accepted %q", raw)
		}
	}
}

func TestUnconfiguredHostNeverUsesExecutorProc(t *testing.T) {
	state := t.TempDir()
	s := HostSampler{}
	r := s.Collect(context.Background(), config.Config{StateDirectory: state, Development: true}, time.Now())
	if r.Source != "unconfigured" || r.Scope != "local_executor" || r.CPUPercent != nil || r.CoreCount != nil || r.MemoryTotalBytes != nil || r.NetworkRxBytes != nil || r.Errors["host_source"] == "" {
		t.Fatalf("unapproved own proc leaked as host: %+v", r)
	}
	if len(r.Filesystems) != 1 || r.Filesystems[0].AvailableBytes == nil {
		t.Fatal("approved local filesystem missing")
	}
}

func TestBoundedReaderRejectsSymlinksAndOversizedSources(t *testing.T) {
	file := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(file, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFixed(file, 4); err == nil {
		t.Fatal("oversized source accepted")
	}
	link := file + "-link"
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFixed(link, 10); err == nil {
		t.Fatal("source symlink accepted")
	}
}
