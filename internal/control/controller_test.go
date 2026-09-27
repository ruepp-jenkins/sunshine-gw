package control

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stefan/sunshine-gateway/internal/config"
	"github.com/stefan/sunshine-gateway/internal/events"
	"github.com/stefan/sunshine-gateway/internal/firewall"
)

// fakeFirewall records what the controller asked the kernel to do.
type fakeFirewall struct {
	mu     sync.Mutex
	calls  []string
	loaded bool
	failOn string
}

func (f *fakeFirewall) record(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	if f.failOn == name {
		return errFake
	}
	return nil
}

func (f *fakeFirewall) Apply(st config.State) error {
	if err := f.record("apply"); err != nil {
		return err
	}
	f.mu.Lock()
	f.loaded = true
	f.mu.Unlock()
	return nil
}

func (f *fakeFirewall) ApplyGuard(st config.State) error { return f.record("guard") }

func (f *fakeFirewall) Clear(st config.State) error {
	if err := f.record("clear"); err != nil {
		return err
	}
	f.mu.Lock()
	f.loaded = false
	f.mu.Unlock()
	return nil
}

func (f *fakeFirewall) TableLoaded() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loaded
}
func (f *fakeFirewall) AllCounters() []firewall.Counter      { return nil }
func (f *fakeFirewall) Health(config.State) []firewall.Check { return nil }
func (f *fakeFirewall) ActiveFlows(config.State) int         { return 0 }

func (f *fakeFirewall) history() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

type fakeError struct{}

func (fakeError) Error() string { return "fake" }

var errFake = fakeError{}

func newTestController(t *testing.T, st config.State) (*Controller, *fakeFirewall, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(path, st); err != nil {
		t.Fatal(err)
	}
	fw := &fakeFirewall{}
	evlog := events.New(log.New(os.Stderr, "", 0))
	ctrl, err := New(path, fw, evlog)
	if err != nil {
		t.Fatal(err)
	}
	return ctrl, fw, path
}

func enabledState() config.State {
	st := config.Defaults()
	st.Target = "10.10.10.5"
	st.GatewayIP = "10.10.10.20"
	st.LANCIDR = "10.10.10.0/24"
	st.Iface = "eth0"
	st.Enabled = true
	st.EnabledAt = time.Now()
	return st
}

func TestStartRestoresEnabledForwarding(t *testing.T) {
	ctrl, fw, _ := newTestController(t, enabledState())
	if err := ctrl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := fw.history(); got != "guard,apply" {
		t.Errorf("Aufrufe = %q, erwartet \"guard,apply\"", got)
	}
}

func TestStartClearsWhenDisabled(t *testing.T) {
	st := enabledState()
	st.Enabled = false
	ctrl, fw, _ := newTestController(t, st)
	if err := ctrl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := fw.history(); got != "guard,clear" {
		t.Errorf("Aufrufe = %q, erwartet \"guard,clear\"", got)
	}
}

// A restart after the daily off time must not come up with the forwarding open.
func TestStartCatchesUpMissedShutdown(t *testing.T) {
	st := enabledState()
	st.DailyOffTime = "03:00"
	// Switched on yesterday evening, so 03:00 fell due in between.
	st.EnabledAt = time.Now().Add(-26 * time.Hour)
	ctrl, fw, path := newTestController(t, st)
	if err := ctrl.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := fw.history(); got != "guard,clear" {
		t.Errorf("Aufrufe = %q, erwartet \"guard,clear\" (nachgeholte Abschaltung)", got)
	}
	stored, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enabled {
		t.Error("nachgeholte Abschaltung wurde nicht persistiert")
	}
}

func TestSetEnabledPersistsAndApplies(t *testing.T) {
	st := enabledState()
	st.Enabled = false
	ctrl, fw, path := newTestController(t, st)

	if err := ctrl.SetEnabled(true, "Test"); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	stored, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Enabled || stored.EnabledAt.IsZero() {
		t.Errorf("Zustand nicht gespeichert: %+v", stored)
	}
	if !strings.HasSuffix(fw.history(), "apply") {
		t.Errorf("Aufrufe = %q, erwartet abschliessendes apply", fw.history())
	}

	if err := ctrl.SetEnabled(false, "Test"); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if !strings.HasSuffix(fw.history(), "clear") {
		t.Errorf("Aufrufe = %q, erwartet abschliessendes clear", fw.history())
	}
}

func TestSetEnabledWithoutTargetFails(t *testing.T) {
	st := enabledState()
	st.Enabled = false
	st.Target = ""
	ctrl, fw, _ := newTestController(t, st)

	if err := ctrl.SetEnabled(true, "Test"); err == nil {
		t.Fatal("Einschalten ohne Ziel muss scheitern")
	}
	if strings.Contains(fw.history(), "apply") {
		t.Errorf("trotz Fehler wurde ein Ruleset geladen: %q", fw.history())
	}
}

// A failing kernel apply must not leave the process claiming success, and the stored
// state must stay in step with what the UI reports.
func TestSetEnabledPropagatesFirewallError(t *testing.T) {
	st := enabledState()
	st.Enabled = false
	ctrl, fw, _ := newTestController(t, st)
	fw.failOn = "apply"

	if err := ctrl.SetEnabled(true, "Test"); err == nil {
		t.Fatal("Fehler beim Laden des Rulesets wurde verschluckt")
	}
}

func TestUpdateRejectsBadInputAndKeepsState(t *testing.T) {
	ctrl, _, path := newTestController(t, enabledState())
	before, _ := config.Load(path)

	err := ctrl.Update(Update{
		Target:       "10.10.10.6",
		TCPPorts:     "47984",
		UDPPorts:     "nonsense",
		Timezone:     "Europe/Berlin",
		GatewayIP:    "10.10.10.20",
		LANCIDR:      "10.10.10.0/24",
		Iface:        "eth0",
		ExternalOnly: true,
	})
	if err == nil {
		t.Fatal("ungueltige Portliste wurde akzeptiert")
	}
	after, _ := config.Load(path)
	if after.Target != before.Target {
		t.Errorf("Zustand wurde trotz Fehler geaendert: %q", after.Target)
	}
}

func TestUpdateAppliesNewPorts(t *testing.T) {
	ctrl, fw, path := newTestController(t, enabledState())

	if err := ctrl.Update(Update{
		Target:       "10.10.10.7",
		DailyOffTime: "04:30",
		Timezone:     "Europe/Berlin",
		TCPPorts:     "47984, 47989",
		UDPPorts:     "47998-48000",
		ExternalOnly: false,
		Flowtable:    true,
		GatewayIP:    "10.10.10.20",
		LANCIDR:      "10.10.10.0/24",
		Iface:        "eth0",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	stored, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Target != "10.10.10.7" || stored.DailyOffTime != "04:30" || !stored.Flowtable {
		t.Errorf("Update nicht gespeichert: %+v", stored)
	}
	if config.FormatPortList(stored.UDPPorts) != "47998-48000" {
		t.Errorf("UDP-Ports = %q", config.FormatPortList(stored.UDPPorts))
	}
	// The port list also shapes the blackhole table, so that one is rebuilt too.
	if !strings.Contains(fw.history(), "guard") {
		t.Errorf("Blackhole-Tabelle nicht neu geladen: %q", fw.history())
	}
	if !strings.HasSuffix(fw.history(), "apply") {
		t.Errorf("Regelwerk nicht neu geladen: %q", fw.history())
	}
}

// Dropping the target implies switching off - an enabled forwarding without a
// destination is not a valid state.
func TestUpdateClearingTargetDisables(t *testing.T) {
	ctrl, _, path := newTestController(t, enabledState())
	if err := ctrl.Update(Update{
		Target:    "",
		TCPPorts:  "47984",
		UDPPorts:  "47998",
		Timezone:  "Europe/Berlin",
		GatewayIP: "10.10.10.20",
		LANCIDR:   "10.10.10.0/24",
		Iface:     "eth0",
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	stored, _ := config.Load(path)
	if stored.Enabled {
		t.Error("ohne Ziel muss die Weiterleitung aus sein")
	}
}

func TestStatusReflectsState(t *testing.T) {
	ctrl, _, _ := newTestController(t, enabledState())
	if err := ctrl.Start(); err != nil {
		t.Fatal(err)
	}
	s := ctrl.Status()
	if !s.Enabled || !s.TableLoaded {
		t.Errorf("Status = %+v, erwartet aktiv und geladen", s)
	}
	if s.TCPPorts != "47984, 47989, 48010" {
		t.Errorf("TCPPorts = %q", s.TCPPorts)
	}
	if s.NextOff == "" {
		t.Error("naechste Abschaltung fehlt im Status")
	}
}
