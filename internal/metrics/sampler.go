package metrics

import (
	"context"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
	"github.com/ruepp-jenkins/sunshine-gw/internal/events"
	"github.com/ruepp-jenkins/sunshine-gw/internal/firewall"
)

// Collector is the kernel side the sampler reads from.
type Collector interface {
	AllCounters() []firewall.Counter
	Flows(st config.State) ([]firewall.Flow, error)
}

// StateSource hands out the current configuration, so the sampler follows a changed target
// or port list without being restarted.
type StateSource interface {
	State() config.State
}

// Sampler reads counters and conntrack on a fixed cadence. Two short-lived commands every
// few seconds, off the data path: a stream cannot notice this, whereas any form of packet
// tap - a userspace proxy, a mirror, pcap - would cost latency or jitter.
type Sampler struct {
	store *Store
	fw    Collector
	state StateSource
	log   *events.Log

	interval time.Duration
	// saveEvery bounds how often the client history is written; the samples stay in memory.
	saveEvery time.Duration
}

func NewSampler(store *Store, fw Collector, state StateSource, log *events.Log) *Sampler {
	return &Sampler{
		store:     store,
		fw:        fw,
		state:     state,
		log:       log,
		interval:  store.interval,
		saveEvery: time.Minute,
	}
}

func (s *Sampler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	saveTicker := time.NewTicker(s.saveEvery)
	defer saveTicker.Stop()

	warned := false
	for {
		select {
		case <-ctx.Done():
			if err := s.store.Save(); err != nil {
				s.log.Warnf("Verlauf konnte nicht gespeichert werden: %v", err)
			}
			return
		case <-saveTicker.C:
			if err := s.store.Save(); err != nil && !warned {
				warned = true
				s.log.Warnf("Verlauf konnte nicht gespeichert werden: %v", err)
			}
		case <-ticker.C:
			s.sample()
		}
	}
}

func (s *Sampler) sample() {
	st := s.state.State()
	var flows []firewall.Flow
	if st.Enabled {
		// Only ask conntrack while something is forwarded; with the table gone there is
		// nothing to find and the command would be pure overhead.
		if f, err := s.fw.Flows(st); err == nil {
			flows = f
		}
	}
	s.store.Observe(s.fw.AllCounters(), flows, firewall.ConntrackAccounting(), time.Now())
}
