// Package metrics answers "who is using the gateway, and how much" without touching a
// single packet.
//
// Everything here reads state the kernel keeps anyway: the rule counters of the forward
// chain for the total throughput, and conntrack's per-connection entries for the client
// addresses and their volumes. Sampling happens in a goroutine every few seconds, entirely
// beside the data path - it cannot add latency or jitter to a stream, because no packet
// ever passes through this process.
package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/firewall"
)

const (
	// 30 minutes at a five second cadence, which is what the graph draws.
	maxSamples = 360
	// A client seen again after this long counts as a new session rather than a
	// continuation, so the UI can say "three sessions" instead of one endless one.
	sessionGap = 2 * time.Minute
	// Cap on remembered clients; the oldest is dropped first. Keeps the file bounded on a
	// gateway that has been running for months.
	maxClients = 200
)

// Sample is one reading of the throughput, in bytes per second.
type Sample struct {
	T    time.Time `json:"t"`
	Up   uint64    `json:"up"`
	Down uint64    `json:"down"`
	// Flows is the number of forwarded connections at that moment.
	Flows int `json:"flows"`
}

// Client is what is known about one source address.
type Client struct {
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	BytesUp   uint64    `json:"bytesUp"`
	BytesDown uint64    `json:"bytesDown"`
	// Flows and Ports describe the current activity; both are empty for a past client.
	Flows    int  `json:"flows"`
	Sessions int  `json:"sessions"`
	Active   bool `json:"active"`
}

type Snapshot struct {
	Samples   []Sample `json:"samples"`
	Clients   []Client `json:"clients"`
	Accounted bool     `json:"accounted"`
	Interval  float64  `json:"intervalSeconds"`
	PeakUp    uint64   `json:"peakUp"`
	PeakDown  uint64   `json:"peakDown"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	interval time.Duration

	samples []Sample
	clients map[string]*Client

	// Previous readings, to turn monotonic counters into rates.
	lastTotals map[string]uint64
	lastFlow   map[string]flowBytes
	lastAt     time.Time

	accounted bool
	dirty     bool
	savedAt   time.Time
}

type flowBytes struct {
	up   uint64
	down uint64
}

// New creates the store. statePath is the gateway's config file; the history lands next to
// it, so both share the /data volume.
func New(statePath string, interval time.Duration) *Store {
	s := &Store{
		path:       filepath.Join(filepath.Dir(statePath), "metrics.json"),
		interval:   interval,
		clients:    map[string]*Client{},
		lastTotals: map[string]uint64{},
		lastFlow:   map[string]flowBytes{},
	}
	s.load()
	return s
}

// Observe folds one reading into the store. counters are the labelled nftables counters,
// flows the current conntrack entries.
func (s *Store) Observe(counters []firewall.Counter, flows []firewall.Flow, accounted bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accounted = accounted

	up := sumLabels(counters, firewall.LabelFwdTCP, firewall.LabelFwdUDP)
	down := sumLabels(counters, firewall.LabelFwdReply)

	elapsed := now.Sub(s.lastAt).Seconds()
	if !s.lastAt.IsZero() && elapsed >= 0.5 {
		s.samples = append(s.samples, Sample{
			T:     now,
			Up:    rate(s.delta("up", up), elapsed),
			Down:  rate(s.delta("down", down), elapsed),
			Flows: len(flows),
		})
		if len(s.samples) > maxSamples {
			s.samples = s.samples[len(s.samples)-maxSamples:]
		}
	} else {
		// First reading, or two readings in the same instant: remember the counters and
		// wait, rather than reporting the total as if it had happened in one second.
		s.delta("up", up)
		s.delta("down", down)
	}
	s.lastAt = now

	s.updateClients(flows, now)
	s.dirty = true
}

// delta turns a monotonic counter into the increase since the last reading. A counter that
// went backwards means the table was reloaded (every toggle rebuilds it), so the current
// value is the increase.
func (s *Store) delta(key string, value uint64) uint64 {
	prev, seen := s.lastTotals[key]
	s.lastTotals[key] = value
	if !seen {
		return 0
	}
	if value < prev {
		return value
	}
	return value - prev
}

func (s *Store) updateClients(flows []firewall.Flow, now time.Time) {
	active := map[string]int{}
	seenKeys := map[string]bool{}

	for _, f := range flows {
		active[f.ClientIP]++
		c := s.clients[f.ClientIP]
		if c == nil {
			c = &Client{IP: f.ClientIP, FirstSeen: now, Sessions: 1}
			s.clients[f.ClientIP] = c
		} else if now.Sub(c.LastSeen) > sessionGap {
			c.Sessions++
		}
		c.LastSeen = now

		// Per-flow counters restart whenever conntrack replaces an entry, so only the
		// increase is added and a lower value is treated as a fresh flow.
		key := f.Key()
		seenKeys[key] = true
		prev := s.lastFlow[key]
		c.BytesUp += increase(prev.up, f.BytesUp)
		c.BytesDown += increase(prev.down, f.BytesDown)
		s.lastFlow[key] = flowBytes{up: f.BytesUp, down: f.BytesDown}
	}

	// Flows that ended: their counters were folded in above, the key can go.
	for key := range s.lastFlow {
		if !seenKeys[key] {
			delete(s.lastFlow, key)
		}
	}

	for ip, c := range s.clients {
		n, ok := active[ip]
		c.Flows = n
		c.Active = ok
	}
	s.evictLocked()
}

func increase(prev, current uint64) uint64 {
	if current < prev {
		return current
	}
	return current - prev
}

func (s *Store) evictLocked() {
	if len(s.clients) <= maxClients {
		return
	}
	type entry struct {
		ip   string
		seen time.Time
	}
	entries := make([]entry, 0, len(s.clients))
	for ip, c := range s.clients {
		entries = append(entries, entry{ip, c.LastSeen})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].seen.Before(entries[j].seen) })
	for _, e := range entries[:len(s.clients)-maxClients] {
		if !s.clients[e.ip].Active {
			delete(s.clients, e.ip)
		}
	}
}

func sumLabels(counters []firewall.Counter, labels ...string) uint64 {
	var total uint64
	for _, c := range counters {
		for _, l := range labels {
			if c.Label == l {
				total += c.Bytes
			}
		}
	}
	return total
}

func rate(delta uint64, seconds float64) uint64 {
	if seconds <= 0 {
		return 0
	}
	return uint64(float64(delta) / seconds)
}

// Snapshot returns a copy for the UI, newest clients first.
func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Empty lists are marshalled as [] rather than null, so a consumer of /api/status
	// never has to special-case the first few seconds after a start.
	out := Snapshot{
		Samples:   append(make([]Sample, 0, len(s.samples)), s.samples...),
		Clients:   make([]Client, 0, len(s.clients)),
		Accounted: s.accounted,
		Interval:  s.interval.Seconds(),
	}
	for _, sample := range s.samples {
		if sample.Up > out.PeakUp {
			out.PeakUp = sample.Up
		}
		if sample.Down > out.PeakDown {
			out.PeakDown = sample.Down
		}
	}
	for _, c := range s.clients {
		snap := *c
		out.Clients = append(out.Clients, snap)
	}
	sort.Slice(out.Clients, func(i, j int) bool {
		if out.Clients[i].Active != out.Clients[j].Active {
			return out.Clients[i].Active
		}
		return out.Clients[i].LastSeen.After(out.Clients[j].LastSeen)
	})
	return out
}

// Forget drops the remembered clients, for when the log should not outlive its purpose.
func (s *Store) Forget() {
	s.mu.Lock()
	s.clients = map[string]*Client{}
	s.lastFlow = map[string]flowBytes{}
	s.dirty = true
	s.mu.Unlock()
	_ = s.Save()
}

type persisted struct {
	Clients []Client `json:"clients"`
}

// Save writes the client history. Same atomic tmp-and-rename as the configuration, and it
// only touches the disk when something changed.
func (s *Store) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	data := persisted{}
	for _, c := range s.clients {
		data.Clients = append(data.Clients, *c)
	}
	s.dirty = false
	s.savedAt = time.Now()
	path := s.path
	s.mu.Unlock()

	sort.Slice(data.Clients, func(i, j int) bool { return data.Clients[i].LastSeen.After(data.Clients[j].LastSeen) })
	blob, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metrics-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(blob, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *Store) load() {
	blob, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var data persisted
	if err := json.Unmarshal(blob, &data); err != nil {
		return
	}
	for i := range data.Clients {
		c := data.Clients[i]
		// Nothing is active across a restart; the next sample decides that again.
		c.Active = false
		c.Flows = 0
		s.clients[c.IP] = &c
	}
}
