package metrics

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/firewall"
)

func counters(up, down uint64) []firewall.Counter {
	return []firewall.Counter{
		{Label: firewall.LabelFwdTCP, Bytes: up / 2},
		{Label: firewall.LabelFwdUDP, Bytes: up - up/2},
		{Label: firewall.LabelFwdReply, Bytes: down},
		{Label: firewall.LabelDNATUDP, Bytes: 999}, // must not end up in the graph
	}
}

func flow(ip string, port int, up, down uint64) firewall.Flow {
	return firewall.Flow{
		Proto: "udp", ClientIP: ip, ClientPort: 51234, Port: port,
		BytesUp: up, BytesDown: down, Accounted: true,
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "config.json"), 5*time.Second)
}

// The first reading cannot produce a rate - there is nothing to compare it to. Reporting
// the absolute counter as if it had happened in one interval would draw a huge spike at
// every start.
func TestFirstObservationProducesNoSample(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	s.Observe(counters(1_000_000, 8_000_000), nil, true, t0)
	if got := len(s.Snapshot().Samples); got != 0 {
		t.Fatalf("%d Samples nach der ersten Messung, erwartet 0", got)
	}
	s.Observe(counters(1_500_000, 9_000_000), nil, true, t0.Add(5*time.Second))
	snap := s.Snapshot()
	if len(snap.Samples) != 1 {
		t.Fatalf("%d Samples, erwartet 1", len(snap.Samples))
	}
	// 500 kB in 5 s = 100 kB/s hoch, 1 MB in 5 s = 200 kB/s runter.
	if snap.Samples[0].Up != 100_000 || snap.Samples[0].Down != 200_000 {
		t.Errorf("Rate = up %d, down %d B/s", snap.Samples[0].Up, snap.Samples[0].Down)
	}
	if snap.PeakUp != 100_000 || snap.PeakDown != 200_000 {
		t.Errorf("Spitzenwerte = up %d, down %d", snap.PeakUp, snap.PeakDown)
	}
}

// Every toggle rebuilds the nftables table, so its counters start at zero again. Without
// reset detection the next sample would underflow into an absurd rate.
func TestCounterResetIsNotABurst(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	s.Observe(counters(10_000_000, 80_000_000), nil, true, t0)
	s.Observe(counters(10_500_000, 84_000_000), nil, true, t0.Add(5*time.Second))
	// Table reloaded: counters restart at a small value.
	s.Observe(counters(50_000, 400_000), nil, true, t0.Add(10*time.Second))

	samples := s.Snapshot().Samples
	last := samples[len(samples)-1]
	if last.Up != 10_000 || last.Down != 80_000 {
		t.Errorf("nach dem Zaehler-Reset = up %d, down %d B/s; erwartet 10000 / 80000", last.Up, last.Down)
	}
}

func TestClientsAccumulateAcrossSamples(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	s.Observe(counters(0, 0), nil, true, t0)
	s.Observe(counters(1000, 2000), []firewall.Flow{flow("203.0.113.9", 47998, 1_000, 8_000)}, true, t0.Add(5*time.Second))
	s.Observe(counters(2000, 4000), []firewall.Flow{flow("203.0.113.9", 47998, 3_000, 24_000)}, true, t0.Add(10*time.Second))

	clients := s.Snapshot().Clients
	if len(clients) != 1 {
		t.Fatalf("%d Clients, erwartet 1", len(clients))
	}
	c := clients[0]
	if c.BytesUp != 3_000 || c.BytesDown != 24_000 {
		t.Errorf("Client-Summen = up %d, down %d; erwartet die Endwerte, nicht die Summe der Messungen", c.BytesUp, c.BytesDown)
	}
	if !c.Active || c.Flows != 1 || c.Sessions != 1 {
		t.Errorf("Client = %+v", c)
	}

	// Flow verschwindet: die Summen bleiben, aktiv ist er nicht mehr.
	s.Observe(counters(2000, 4000), nil, true, t0.Add(15*time.Second))
	c = s.Snapshot().Clients[0]
	if c.Active || c.Flows != 0 {
		t.Errorf("Client muesste inaktiv sein: %+v", c)
	}
	if c.BytesUp != 3_000 {
		t.Errorf("Summe nach Flow-Ende verloren: %d", c.BytesUp)
	}
}

// conntrack replaces an entry when a client reconnects on the same ports; its counters then
// start from zero again and must be added, not subtracted.
func TestReusedFlowKeyCountsForward(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	s.Observe(counters(0, 0), nil, true, t0)
	s.Observe(counters(1, 1), []firewall.Flow{flow("203.0.113.9", 47998, 5_000, 40_000)}, true, t0.Add(5*time.Second))
	s.Observe(counters(2, 2), []firewall.Flow{flow("203.0.113.9", 47998, 700, 900)}, true, t0.Add(10*time.Second))

	c := s.Snapshot().Clients[0]
	if c.BytesUp != 5_700 || c.BytesDown != 40_900 {
		t.Errorf("= up %d, down %d; erwartet 5700 / 40900", c.BytesUp, c.BytesDown)
	}
}

func TestSessionsCountedAfterGap(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	s.Observe(counters(0, 0), nil, true, t0)
	s.Observe(counters(1, 1), []firewall.Flow{flow("203.0.113.9", 47998, 10, 10)}, true, t0.Add(5*time.Second))
	if got := s.Snapshot().Clients[0].Sessions; got != 1 {
		t.Fatalf("Sessions = %d, erwartet 1", got)
	}
	// Derselbe Client eine Stunde spaeter: neue Sitzung.
	later := t0.Add(time.Hour)
	s.Observe(counters(2, 2), []firewall.Flow{flow("203.0.113.9", 47998, 20, 20)}, true, later)
	if got := s.Snapshot().Clients[0].Sessions; got != 2 {
		t.Errorf("Sessions = %d, erwartet 2", got)
	}
	// Kurz danach noch einmal: weiterhin dieselbe Sitzung.
	s.Observe(counters(3, 3), []firewall.Flow{flow("203.0.113.9", 47998, 30, 30)}, true, later.Add(10*time.Second))
	if got := s.Snapshot().Clients[0].Sessions; got != 2 {
		t.Errorf("Sessions = %d, erwartet 2", got)
	}
}

func TestMultipleClientsSortedActiveFirst(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	s.Observe(counters(0, 0), nil, true, t0)
	s.Observe(counters(1, 1), []firewall.Flow{flow("198.51.100.7", 47998, 10, 10)}, true, t0.Add(5*time.Second))
	s.Observe(counters(2, 2), []firewall.Flow{flow("203.0.113.9", 47998, 10, 10)}, true, t0.Add(10*time.Second))

	clients := s.Snapshot().Clients
	if len(clients) != 2 {
		t.Fatalf("%d Clients, erwartet 2", len(clients))
	}
	if !clients[0].Active || clients[0].IP != "203.0.113.9" {
		t.Errorf("aktiver Client gehoert nach vorne: %+v", clients)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "config.json")
	s := New(statePath, 5*time.Second)
	t0 := time.Now().Truncate(time.Second)
	s.Observe(counters(0, 0), nil, true, t0)
	s.Observe(counters(1, 1), []firewall.Flow{flow("203.0.113.9", 47998, 1234, 5678)}, true, t0.Add(5*time.Second))
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	again := New(statePath, 5*time.Second)
	clients := again.Snapshot().Clients
	if len(clients) != 1 || clients[0].IP != "203.0.113.9" || clients[0].BytesUp != 1234 {
		t.Fatalf("Verlauf nicht wiederhergestellt: %+v", clients)
	}
	// Nach einem Neustart ist niemand aktiv, bis die erste Messung das sagt.
	if clients[0].Active || clients[0].Flows != 0 {
		t.Errorf("Client nach Neustart als aktiv geladen: %+v", clients[0])
	}
	if err := again.Save(); err != nil {
		t.Fatalf("zweites Save: %v", err)
	}
	// Kein Temporaerfile-Muell aus dem atomaren Schreiben.
	entries, _ := filepath.Glob(filepath.Join(dir, ".metrics-*"))
	if len(entries) != 0 {
		t.Errorf("Temporaerdateien liegen herum: %v", entries)
	}
}

func TestForgetClearsHistory(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	s.Observe(counters(0, 0), nil, true, t0)
	s.Observe(counters(1, 1), []firewall.Flow{flow("203.0.113.9", 47998, 10, 10)}, true, t0.Add(5*time.Second))
	s.Forget()
	if got := len(s.Snapshot().Clients); got != 0 {
		t.Errorf("%d Clients nach Forget", got)
	}
}

func TestSampleRingIsBounded(t *testing.T) {
	s := newStore(t)
	t0 := time.Now()
	for i := 0; i < maxSamples+50; i++ {
		s.Observe(counters(uint64(i)*1000, uint64(i)*2000), nil, true, t0.Add(time.Duration(i)*5*time.Second))
	}
	if got := len(s.Snapshot().Samples); got != maxSamples {
		t.Errorf("%d Samples, erwartet hoechstens %d", got, maxSamples)
	}
}

// A fresh store must hand out empty lists, not nulls: /api/status is consumed by the page
// on the very first load, seconds before the first sample exists.
func TestSnapshotUsesEmptyListsNotNull(t *testing.T) {
	snap := newStore(t).Snapshot()
	if snap.Samples == nil || snap.Clients == nil {
		t.Errorf("Snapshot mit nil-Listen: %+v", snap)
	}
	blob, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "null") {
		t.Errorf("JSON enthaelt null: %s", blob)
	}
}
