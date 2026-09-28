package control

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
	"github.com/ruepp-jenkins/sunshine-gw/internal/events"
	"github.com/ruepp-jenkins/sunshine-gw/internal/firewall"
	"github.com/ruepp-jenkins/sunshine-gw/internal/metrics"
)

// Status is everything the page shows, in one shot.
type Status struct {
	Now          time.Time          `json:"now"`
	Enabled      bool               `json:"enabled"`
	Target       string             `json:"target"`
	GatewayIP    string             `json:"gatewayIP"`
	Iface        string             `json:"iface"`
	LANCIDR      string             `json:"lanCIDR"`
	TCPPorts     string             `json:"tcpPorts"`
	UDPPorts     string             `json:"udpPorts"`
	ExternalOnly bool               `json:"externalOnly"`
	Flowtable    bool               `json:"flowtable"`
	DailyOffTime string             `json:"dailyOffTime"`
	Timezone     string             `json:"timezone"`
	NextOff      string             `json:"nextOff"`
	NextOffIn    string             `json:"nextOffIn"`
	EnabledSince string             `json:"enabledSince"`
	TableLoaded  bool               `json:"tableLoaded"`
	ActiveFlows  int                `json:"activeFlows"`
	Counters     []firewall.Counter `json:"counters"`
	Checks       []firewall.Check   `json:"checks"`
	Worst        firewall.Level     `json:"worst"`
	Events       []events.Event     `json:"events"`
	Metrics      metrics.Snapshot   `json:"metrics"`
	Interfaces   []IfaceOption      `json:"interfaces"`
}

// IfaceOption is one entry of the interface dropdown, already formatted: the settings
// page shows connection state and IPv4 address so picking the one the FRITZ!Box forward
// actually points at does not require a shell on the host.
type IfaceOption struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Selected bool   `json:"selected"`
}

// ifaceOptions lists the host's interfaces for the dropdown, with the configured one
// selected. If the configured interface no longer exists (renamed, unplugged card), it is
// still offered as its own option - otherwise saving the form would silently switch the
// interface out from under the user.
func ifaceOptions(current string) []IfaceOption {
	list, _ := config.ListInterfaces()
	out := make([]IfaceOption, 0, len(list)+1)
	found := false
	for _, ifi := range list {
		if ifi.Name == current {
			found = true
		}
		out = append(out, IfaceOption{Name: ifi.Name, Label: ifaceLabel(ifi), Selected: ifi.Name == current})
	}
	if current != "" && !found {
		out = append(out, IfaceOption{Name: current, Label: current + " (nicht gefunden)", Selected: true})
	}
	return out
}

func ifaceLabel(ifi config.IfaceInfo) string {
	state := "aus"
	switch {
	case ifi.Carrier:
		state = "verbunden"
	case ifi.Up:
		state = "kein Link"
	}
	if len(ifi.Addrs) == 0 {
		return fmt.Sprintf("%s - %s", ifi.Name, state)
	}
	return fmt.Sprintf("%s - %s, %s", ifi.Name, state, strings.Join(ifi.Addrs, ", "))
}

func (c *Controller) invalidate() {
	c.statusMu.Lock()
	c.cached = nil
	c.statusMu.Unlock()
}

// Status assembles the current picture. The kernel round trips (nft, conntrack, the
// reachability probe) are cached for a moment so the 2 s poll of the page does not
// turn into a stream of subprocesses.
func (c *Controller) Status() Status {
	c.statusMu.Lock()
	if c.cached != nil && time.Now().Before(c.cachedUntil) {
		st := *c.cached
		c.statusMu.Unlock()
		st.Now = time.Now()
		st.Events = c.log.Recent()
		// The sampler keeps filling these behind the cache, so they are taken fresh -
		// reading them costs a lock, not a subprocess.
		st.Metrics = c.metrics.Snapshot()
		return st
	}
	c.statusMu.Unlock()

	st := c.State()
	out := buildStatus(st, c.fw, c.log)
	out.Metrics = c.metrics.Snapshot()

	c.statusMu.Lock()
	cached := out
	c.cached = &cached
	c.cachedUntil = time.Now().Add(c.cacheTTL)
	c.statusMu.Unlock()
	return out
}

func buildStatus(st config.State, fw Firewall, log *events.Log) Status {
	now := time.Now()
	out := Status{
		Now:          now,
		Enabled:      st.Enabled,
		Target:       st.Target,
		GatewayIP:    st.GatewayIP,
		Iface:        st.Iface,
		LANCIDR:      st.LANCIDR,
		TCPPorts:     config.FormatPortList(st.TCPPorts),
		UDPPorts:     config.FormatPortList(st.UDPPorts),
		ExternalOnly: st.ExternalOnly,
		Flowtable:    st.Flowtable,
		DailyOffTime: st.DailyOffTime,
		Timezone:     st.Timezone,
		TableLoaded:  fw.TableLoaded(),
		Counters:     fw.AllCounters(),
		Events:       log.Recent(),
		Interfaces:   ifaceOptions(st.Iface),
	}
	out.Checks = fw.Health(st)
	out.Worst = firewall.WorstLevel(out.Checks)
	if st.Enabled {
		out.ActiveFlows = fw.ActiveFlows(st)
	} else {
		out.ActiveFlows = 0
	}
	if next := st.NextOffTime(now); !next.IsZero() {
		out.NextOff = next.Format("Mon 02.01. 15:04 MST")
		out.NextOffIn = humanDuration(next.Sub(now))
	}
	if st.Enabled && !st.EnabledAt.IsZero() {
		out.EnabledSince = st.EnabledAt.In(st.Location()).Format("02.01. 15:04")
	}
	return out
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h == 0 {
		return strconv.Itoa(m) + " min"
	}
	return strconv.Itoa(h) + " h " + strconv.Itoa(m) + " min"
}
