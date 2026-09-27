package scheduler

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stefan/sunshine-gateway/internal/config"
	"github.com/stefan/sunshine-gateway/internal/control"
	"github.com/stefan/sunshine-gateway/internal/events"
	"github.com/stefan/sunshine-gateway/internal/firewall"
)

type stubFirewall struct{ loaded bool }

func (s *stubFirewall) Apply(config.State) error             { s.loaded = true; return nil }
func (s *stubFirewall) ApplyGuard(config.State) error        { return nil }
func (s *stubFirewall) Clear(config.State) error             { s.loaded = false; return nil }
func (s *stubFirewall) TableLoaded() bool                    { return s.loaded }
func (s *stubFirewall) AllCounters() []firewall.Counter      { return nil }
func (s *stubFirewall) Health(config.State) []firewall.Check { return nil }
func (s *stubFirewall) ActiveFlows(config.State) int         { return 0 }

func setup(t *testing.T, offTime string) (*control.Controller, *events.Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	st := config.Defaults()
	st.Target = "10.10.10.5"
	st.GatewayIP = "10.10.10.20"
	st.LANCIDR = "10.10.10.0/24"
	st.Iface = "eth0"
	st.Enabled = true
	st.EnabledAt = time.Now()
	st.DailyOffTime = offTime
	if err := config.Save(path, st); err != nil {
		t.Fatal(err)
	}
	evlog := events.New(log.New(os.Stderr, "", 0))
	ctrl, err := control.New(path, &stubFirewall{}, evlog)
	if err != nil {
		t.Fatal(err)
	}
	return ctrl, evlog, path
}

// The kill switch must fire on its own, without anyone touching the UI.
func TestSchedulerDisablesAtOffTime(t *testing.T) {
	ctrl, evlog, path := setup(t, "03:00")
	sched := New(ctrl, evlog)
	// Pretend it is two seconds before the configured off time.
	st := ctrl.State()
	target := st.NextOffTime(time.Now())
	offset := time.Until(target) - 2*time.Second
	sched.now = func() time.Time { return time.Now().Add(offset) }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go sched.Run(ctx)

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if !ctrl.State().Enabled {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ctrl.State().Enabled {
		t.Fatal("Weiterleitung laeuft nach der Abschaltzeit weiter")
	}
	stored, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enabled {
		t.Error("Abschaltung wurde nicht persistiert - ein Neustart wuerde sie wieder aufziehen")
	}
	var found bool
	for _, e := range evlog.Recent() {
		if strings.Contains(e.Message, "taegliche Abschaltung") {
			found = true
		}
	}
	if !found {
		t.Error("kein Eintrag im Verlauf, der die automatische Abschaltung erklaert")
	}
}

// Without an off time the scheduler must sit still, not switch anything off.
func TestSchedulerWithoutOffTimeDoesNothing(t *testing.T) {
	ctrl, evlog, _ := setup(t, "")
	sched := New(ctrl, evlog)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	sched.Run(ctx)

	if !ctrl.State().Enabled {
		t.Error("ohne Abschaltzeit darf nichts abgeschaltet werden")
	}
}

// Changing the time while running has to take effect immediately.
func TestSchedulerReactsToConfigChange(t *testing.T) {
	ctrl, evlog, _ := setup(t, "")
	sched := New(ctrl, evlog)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { sched.Run(ctx); close(done) }()

	if err := ctrl.Update(control.Update{
		Target:       "10.10.10.5",
		DailyOffTime: "03:00",
		Timezone:     "Europe/Berlin",
		TCPPorts:     "47984",
		UDPPorts:     "47998",
		ExternalOnly: true,
		GatewayIP:    "10.10.10.20",
		LANCIDR:      "10.10.10.0/24",
		Iface:        "eth0",
	}); err != nil {
		t.Fatal(err)
	}
	// The scheduler logs the next shutdown once it has picked up the change.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range evlog.Recent() {
			if strings.Contains(e.Message, "naechste automatische Abschaltung") {
				cancel()
				<-done
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Error("Scheduler hat die neue Uhrzeit nicht uebernommen")
}
