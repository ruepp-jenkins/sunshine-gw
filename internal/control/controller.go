// Package control owns the state and keeps the kernel ruleset in sync with it.
// Every change takes the same path: validate -> persist -> re-apply.
package control

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
	"github.com/ruepp-jenkins/sunshine-gw/internal/events"
	"github.com/ruepp-jenkins/sunshine-gw/internal/firewall"
)

// Firewall is the kernel side of the gateway. The interface exists so the state
// machine - especially the catch-up on start and the order of clear/flush - can be
// tested without root and without nftables.
type Firewall interface {
	Apply(st config.State) error
	ApplyGuard(st config.State) error
	Clear(st config.State) error
	TableLoaded() bool
	AllCounters() []firewall.Counter
	Health(st config.State) []firewall.Check
	ActiveFlows(st config.State) int
}

type Controller struct {
	mu    sync.Mutex
	state config.State
	path  string

	fw  Firewall
	log *events.Log

	reload chan struct{}

	// The status page polls every couple of seconds; the kernel round trips behind it
	// are cached briefly so polling stays cheap.
	statusMu    sync.Mutex
	cached      *Status
	cachedUntil time.Time
	cacheTTL    time.Duration
}

func New(path string, fw Firewall, log *events.Log) (*Controller, error) {
	st, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	c := &Controller{
		state:    st,
		path:     path,
		fw:       fw,
		log:      log,
		reload:   make(chan struct{}, 1),
		cacheTTL: 1500 * time.Millisecond,
	}
	return c, nil
}

// Reload fires whenever the configuration changed and the scheduler has to recompute.
func (c *Controller) Reload() <-chan struct{} { return c.reload }

func (c *Controller) notify() {
	select {
	case c.reload <- struct{}{}:
	default:
	}
}

func (c *Controller) State() config.State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Start brings the kernel in line with the persisted state. The blackhole table is
// loaded unconditionally, and a daily off time that fell due while the gateway was
// down is applied now - otherwise a restart during the night would leave the
// forwarding open until the next day.
func (c *Controller) Start() error {
	c.mu.Lock()
	st := c.state
	c.mu.Unlock()

	if err := c.fw.ApplyGuard(st); err != nil {
		c.log.Errorf("Blackhole-Tabelle konnte nicht geladen werden: %v", err)
	}

	if st.MissedOff(time.Now()) {
		c.log.Warnf("Abschaltzeit %s ist waehrend der Auszeit faellig geworden - Weiterleitung bleibt aus",
			st.DailyOffTime)
		return c.setEnabled(false, "Nachholen der taeglichen Abschaltung")
	}
	if st.Enabled {
		if err := c.fw.Apply(st); err != nil {
			return fmt.Errorf("Regelwerk konnte nicht geladen werden: %w", err)
		}
		c.log.Infof("Weiterleitung nach %s wiederhergestellt", st.Target)
		return nil
	}
	if err := c.fw.Clear(st); err != nil {
		c.log.Warnf("Aufraeumen beim Start fehlgeschlagen: %v", err)
	}
	c.log.Infof("Gateway gestartet, Weiterleitung ist aus")
	return nil
}

// SetEnabled switches the forwarding on or off. reason ends up in the event log so it
// is visible afterwards whether a human or the scheduler did it.
func (c *Controller) SetEnabled(on bool, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setEnabledLocked(on, reason)
}

func (c *Controller) setEnabled(on bool, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.setEnabledLocked(on, reason)
}

func (c *Controller) setEnabledLocked(on bool, reason string) error {
	next := c.state
	next.Enabled = on
	if on {
		next.EnabledAt = time.Now()
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if err := c.persistLocked(next); err != nil {
		return err
	}
	if on {
		c.log.Infof("Weiterleitung nach %s eingeschaltet (%s)", next.Target, reason)
	} else {
		c.log.Infof("Weiterleitung ausgeschaltet (%s)", reason)
	}
	c.invalidate()
	c.notify()
	return c.applyLocked()
}

// Update is the form submission: everything the UI can change at once.
type Update struct {
	Target       string
	DailyOffTime string
	Timezone     string
	TCPPorts     string
	UDPPorts     string
	ExternalOnly bool
	Flowtable    bool
	GatewayIP    string
	LANCIDR      string
	Iface        string
}

func (c *Controller) Update(u Update) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.state
	prev := c.state

	tcp, err := config.ParsePortList(u.TCPPorts)
	if err != nil {
		return fmt.Errorf("TCP-Ports: %w", err)
	}
	udp, err := config.ParsePortList(u.UDPPorts)
	if err != nil {
		return fmt.Errorf("UDP-Ports: %w", err)
	}
	next.Target = trim(u.Target)
	next.DailyOffTime = trim(u.DailyOffTime)
	next.Timezone = trim(u.Timezone)
	next.TCPPorts = tcp
	next.UDPPorts = udp
	next.ExternalOnly = u.ExternalOnly
	next.Flowtable = u.Flowtable
	next.GatewayIP = trim(u.GatewayIP)
	next.LANCIDR = trim(u.LANCIDR)
	next.Iface = trim(u.Iface)

	if next.Target == "" {
		next.Enabled = false
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if err := c.persistLocked(next); err != nil {
		return err
	}
	for _, line := range diff(prev, next) {
		c.log.Infof("%s", line)
	}
	c.invalidate()
	c.notify()
	// The port list also shapes the blackhole table, so that one is rebuilt too.
	if err := c.fw.ApplyGuard(next); err != nil {
		c.log.Warnf("Blackhole-Tabelle: %v", err)
	}
	return c.applyLocked()
}

// applyLocked makes the kernel match c.state. The persisted state is not rolled back
// when this fails: it stays the intent, the event log says what went wrong, and the
// "Regelwerk" health check keeps showing the mismatch until it is resolved. Callers
// have already persisted and logged, so the error here is about the kernel only.
func (c *Controller) applyLocked() error {
	var err error
	if c.state.Enabled {
		err = c.fw.Apply(c.state)
		if err != nil {
			err = fmt.Errorf("Zustand gespeichert, aber das Regelwerk liess sich nicht laden: %w", err)
		}
	} else {
		err = c.fw.Clear(c.state)
		if err != nil {
			err = fmt.Errorf("Zustand gespeichert, aber das Regelwerk liess sich nicht entfernen: %w", err)
		}
	}
	if err != nil {
		c.log.Errorf("%v", err)
		c.invalidate()
	}
	return err
}

func (c *Controller) persistLocked(next config.State) error {
	if err := config.Save(c.path, next); err != nil {
		return fmt.Errorf("Zustand konnte nicht gespeichert werden: %w", err)
	}
	c.state = next
	return nil
}

func diff(a, b config.State) []string {
	var out []string
	if a.Target != b.Target {
		out = append(out, fmt.Sprintf("Ziel geaendert: %s -> %s", orDash(a.Target), orDash(b.Target)))
	}
	if a.DailyOffTime != b.DailyOffTime {
		out = append(out, fmt.Sprintf("taegliche Abschaltung: %s -> %s", orDash(a.DailyOffTime), orDash(b.DailyOffTime)))
	}
	if a.Timezone != b.Timezone {
		out = append(out, fmt.Sprintf("Zeitzone: %s -> %s", orDash(a.Timezone), orDash(b.Timezone)))
	}
	if config.FormatPortList(a.TCPPorts) != config.FormatPortList(b.TCPPorts) {
		out = append(out, fmt.Sprintf("TCP-Ports: %s -> %s",
			config.FormatPortList(a.TCPPorts), config.FormatPortList(b.TCPPorts)))
	}
	if config.FormatPortList(a.UDPPorts) != config.FormatPortList(b.UDPPorts) {
		out = append(out, fmt.Sprintf("UDP-Ports: %s -> %s",
			config.FormatPortList(a.UDPPorts), config.FormatPortList(b.UDPPorts)))
	}
	if a.ExternalOnly != b.ExternalOnly {
		out = append(out, fmt.Sprintf("nur externe Quellen: %v -> %v", a.ExternalOnly, b.ExternalOnly))
	}
	if a.Flowtable != b.Flowtable {
		out = append(out, fmt.Sprintf("Fast-Path: %v -> %v", a.Flowtable, b.Flowtable))
	}
	if a.GatewayIP != b.GatewayIP || a.Iface != b.Iface || a.LANCIDR != b.LANCIDR {
		out = append(out, fmt.Sprintf("Netz: %s auf %s in %s", orDash(b.GatewayIP), orDash(b.Iface), orDash(b.LANCIDR)))
	}
	if len(out) == 0 {
		out = append(out, "Einstellungen gespeichert (unveraendert)")
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func trim(s string) string {
	return strings.TrimSpace(s)
}
