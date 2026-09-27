package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// State is the single source of truth for the gateway. It is persisted as JSON and
// every change follows the same path: validate -> persist -> re-render the ruleset.
type State struct {
	// Target is the IPv4 address of the Sunshine host.
	Target string `json:"target"`
	// Enabled reflects whether the forwarding ruleset should be loaded.
	Enabled bool `json:"enabled"`
	// EnabledAt is when Enabled was last set to true. Used for the start-up catch-up:
	// a daily off time that fell due while the gateway was down still takes effect.
	EnabledAt time.Time `json:"enabledAt,omitempty"`

	// DailyOffTime is "HH:MM" in Timezone, or "" to disable the daily kill switch.
	DailyOffTime string `json:"dailyOffTime"`
	Timezone     string `json:"timezone"`

	TCPPorts []PortRange `json:"tcpPorts"`
	UDPPorts []PortRange `json:"udpPorts"`

	// ExternalOnly restricts forwarding to sources outside LANCIDR. LAN clients talk
	// to Sunshine directly; only traffic that came in through the FRITZ!Box is relayed.
	ExternalOnly bool `json:"externalOnly"`
	// Flowtable enables the nftables software fast path for established flows.
	Flowtable bool `json:"flowtable"`

	// Network identity of the gateway itself, auto-detected on first start.
	GatewayIP string `json:"gatewayIP"`
	LANCIDR   string `json:"lanCIDR"`
	Iface     string `json:"iface"`
}

// Sunshine defaults, base port 47989. Port 47990 (Sunshine's own web UI) is
// deliberately absent - it must never be reachable from the internet.
func Defaults() State {
	return State{
		Target:       "",
		Enabled:      false,
		DailyOffTime: "03:00",
		Timezone:     "Europe/Berlin",
		TCPPorts: []PortRange{
			{47984, 47984}, // HTTPS / GameStream
			{47989, 47989}, // HTTP / GameStream
			{48010, 48010}, // RTSP
		},
		UDPPorts: []PortRange{
			{47998, 48000}, // Video, Audio, Control
			{48002, 48002}, // Mic (unused, for completeness)
		},
		ExternalOnly: true,
		Flowtable:    false,
	}
}

func (s *State) Location() *time.Location {
	if s.Timezone == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return time.Local
	}
	return loc
}

// NextOffTime returns the next moment the daily kill switch fires after ref,
// or the zero time when no daily off time is configured. The next occurrence is
// built with time.Date in the configured location so DST transitions stay correct.
func (s *State) NextOffTime(ref time.Time) time.Time {
	h, m, ok := s.parseOffTime()
	if !ok {
		return time.Time{}
	}
	loc := s.Location()
	ref = ref.In(loc)
	next := time.Date(ref.Year(), ref.Month(), ref.Day(), h, m, 0, 0, loc)
	if !next.After(ref) {
		next = time.Date(ref.Year(), ref.Month(), ref.Day()+1, h, m, 0, 0, loc)
	}
	return next
}

// PrevOffTime returns the most recent moment the kill switch was due at or before ref.
func (s *State) PrevOffTime(ref time.Time) time.Time {
	h, m, ok := s.parseOffTime()
	if !ok {
		return time.Time{}
	}
	loc := s.Location()
	ref = ref.In(loc)
	prev := time.Date(ref.Year(), ref.Month(), ref.Day(), h, m, 0, 0, loc)
	if prev.After(ref) {
		prev = time.Date(ref.Year(), ref.Month(), ref.Day()-1, h, m, 0, 0, loc)
	}
	return prev
}

func (s *State) parseOffTime() (hour, minute int, ok bool) {
	if strings.TrimSpace(s.DailyOffTime) == "" {
		return 0, 0, false
	}
	t, err := time.Parse("15:04", strings.TrimSpace(s.DailyOffTime))
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

// MissedOff reports whether a daily off time fell due after the forwarding was last
// switched on. True means: switch off immediately instead of coming up open.
func (s *State) MissedOff(now time.Time) bool {
	if !s.Enabled {
		return false
	}
	prev := s.PrevOffTime(now)
	if prev.IsZero() {
		return false
	}
	if s.EnabledAt.IsZero() {
		return true
	}
	return prev.After(s.EnabledAt)
}

func (s *State) Validate() error {
	if s.Target != "" {
		ip := net.ParseIP(s.Target)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("Zieladresse %q ist keine IPv4-Adresse", s.Target)
		}
	}
	if s.Enabled && s.Target == "" {
		return fmt.Errorf("ohne Zieladresse kann die Weiterleitung nicht aktiviert werden")
	}
	if strings.TrimSpace(s.DailyOffTime) != "" {
		if _, _, ok := s.parseOffTime(); !ok {
			return fmt.Errorf("Uhrzeit %q ist nicht im Format HH:MM", s.DailyOffTime)
		}
	}
	if s.Timezone != "" {
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			return fmt.Errorf("unbekannte Zeitzone %q", s.Timezone)
		}
	}
	if len(s.TCPPorts) == 0 && len(s.UDPPorts) == 0 {
		return fmt.Errorf("es muss mindestens ein Port weitergeleitet werden")
	}
	if s.GatewayIP != "" && net.ParseIP(s.GatewayIP) == nil {
		return fmt.Errorf("Gateway-Adresse %q ist keine IP-Adresse", s.GatewayIP)
	}
	if s.LANCIDR != "" {
		if _, _, err := net.ParseCIDR(s.LANCIDR); err != nil {
			return fmt.Errorf("LAN-Netz %q ist kein CIDR (z.B. 10.10.10.0/24)", s.LANCIDR)
		}
	}
	if s.ExternalOnly && s.LANCIDR == "" {
		return fmt.Errorf("\"nur externe Quellen\" braucht ein LAN-Netz")
	}
	return nil
}

// Load reads the state file. A missing file yields the defaults plus auto-detected
// network identity, so a fresh container comes up usable but switched off.
func Load(path string) (State, error) {
	st := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return st, err
		}
		st.fillNetwork()
		return st, nil
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("%s ist kein gueltiges JSON: %w", path, err)
	}
	if len(st.TCPPorts) == 0 && len(st.UDPPorts) == 0 {
		d := Defaults()
		st.TCPPorts, st.UDPPorts = d.TCPPorts, d.UDPPorts
	}
	if st.Timezone == "" {
		st.Timezone = Defaults().Timezone
	}
	st.fillNetwork()
	return st, nil
}

func (s *State) fillNetwork() {
	if s.GatewayIP != "" && s.Iface != "" && s.LANCIDR != "" {
		return
	}
	iface, ip, cidr, err := DetectNetwork()
	if err != nil {
		return
	}
	if s.Iface == "" {
		s.Iface = iface
	}
	if s.GatewayIP == "" {
		s.GatewayIP = ip
	}
	if s.LANCIDR == "" {
		s.LANCIDR = cidr
	}
}

// Save writes the state atomically: a temporary file in the same directory plus
// rename, so a power cut cannot leave half a state behind.
func Save(path string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// DetectNetwork finds the interface the gateway lives on and returns its name, its
// IPv4 address and the network it sits in. First choice is the interface carrying the
// default route; if there is none, the first ordinary LAN interface is used. Read
// straight from /proc and the netlink-backed stdlib, so no `ip` binary is needed.
func DetectNetwork() (iface, ip, cidr string, err error) {
	iface, err = defaultRouteIface()
	if err != nil {
		iface, err = firstLANIface()
		if err != nil {
			return "", "", "", err
		}
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return "", "", "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", "", "", err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		network := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
		return iface, ipnet.IP.String(), network.String(), nil
	}
	return "", "", "", fmt.Errorf("keine IPv4-Adresse auf %s gefunden", iface)
}

// firstLANIface picks the first interface that looks like a LAN connection, skipping
// loopback, down links and the virtual interfaces of container and VM bridges.
func firstLANIface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || skipIface(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLinkLocalUnicast() {
				return ifi.Name, nil
			}
		}
	}
	return "", fmt.Errorf("kein LAN-Interface gefunden")
}

func skipIface(name string) bool {
	for _, prefix := range []string{"docker", "br-", "veth", "virbr", "tap", "tun", "wg", "zt", "lo"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func defaultRouteIface() (string, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("keine Default-Route in /proc/net/route gefunden")
}
