package firewall

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
)

type Level string

const (
	OK    Level = "ok"
	Warn  Level = "warn"
	Error Level = "error"
)

// Check is one prerequisite with a verdict. The point is that the gateway says why it
// does not work instead of silently forwarding nothing.
type Check struct {
	Name    string `json:"name"`
	Level   Level  `json:"level"`
	Message string `json:"message"`
}

// Health inspects the host prerequisites and the actual kernel state.
func (m *Manager) Health(st config.State) []Check {
	var checks []Check
	add := func(name string, level Level, format string, args ...any) {
		checks = append(checks, Check{Name: name, Level: level, Message: fmt.Sprintf(format, args...)})
	}

	if has("nft") {
		add("nftables", OK, "nft vorhanden")
	} else {
		add("nftables", Error, "nft fehlt im Image - ohne das geht gar nichts")
	}

	switch v, err := readSysctl("net/ipv4/ip_forward"); {
	case err != nil:
		add("ip_forward", Warn, "konnte nicht gelesen werden: %v", err)
	case v == "1":
		add("ip_forward", OK, "net.ipv4.ip_forward=1")
	default:
		add("ip_forward", Error,
			"net.ipv4.ip_forward=%s - auf dem Host setzen: /etc/sysctl.d/99-sunshine-gw.conf, dann sysctl --system", v)
	}

	if has("conntrack") {
		add("conntrack", OK, "conntrack vorhanden (Abschalten beendet laufende Streams sofort)")
	} else {
		add("conntrack", Warn, "conntrack fehlt - laufende Streams laufen nach dem Abschalten bis zum Timeout weiter")
	}

	// Accounting is what fills the per-client byte counters. Off by default on most
	// distributions, and not settable from inside the container, so it is reported rather
	// than fixed. The client list works without it; only the volumes stay unknown.
	if ConntrackAccounting() {
		add("conntrack-Accounting", OK, "net.netfilter.nf_conntrack_acct=1 - Datenmengen pro Client werden gezaehlt")
	} else {
		add("conntrack-Accounting", Warn,
			"net.netfilter.nf_conntrack_acct=0 - Clients und Flows sind sichtbar, Datenmengen pro Client nicht. "+
				"Auf dem Host setzen: /etc/sysctl.d/99-sunshine-gw.conf, dann sysctl --system")
	}

	switch {
	case !m.ForwardPolicyDrop():
		add("FORWARD-Policy", OK, "FORWARD verwirft nicht per Default")
	case m.DockerUserPresent() && (!st.Enabled || m.ForwardAcceptActive()):
		add("FORWARD-Policy", OK, "FORWARD ist DROP, Freigabe laeuft ueber die Kette %s in %s", iptChain, dockerUserChain)
	case m.DockerUserPresent():
		add("FORWARD-Policy", Error, "FORWARD ist DROP und die Kette %s ist leer - Pakete werden verworfen", iptChain)
	default:
		add("FORWARD-Policy", Error,
			"FORWARD ist DROP, aber %s existiert nicht. Weiterleitung wird blockiert; FORWARD-Freigabe manuell setzen", dockerUserChain)
	}

	loaded := m.TableLoaded()
	switch {
	case st.Enabled && loaded:
		add("Regelwerk", OK, "Tabelle inet %s ist geladen", TableName)
	case st.Enabled && !loaded:
		add("Regelwerk", Error, "Weiterleitung ist eingeschaltet, aber die Tabelle fehlt im Kernel")
	case !st.Enabled && loaded:
		add("Regelwerk", Error, "Weiterleitung ist aus, aber die Tabelle ist noch geladen")
	default:
		add("Regelwerk", OK, "keine Weiterleitungsregeln geladen")
	}

	// When the forwarding is off, say so as a fact rather than as an assumption: no
	// translation rule, no forward permission, no leftover connection.
	if !st.Enabled {
		checks = append(checks, offStateCheck(loaded, m.ForwardAcceptActive(), m.ActiveFlows(st)))
	}

	loadedGuard, rawDrop := m.guardState()
	checks = append(checks, guardCheck(loadedGuard, rawDrop, st.Enabled))

	if foreign := m.foreignForwardDrops(); len(foreign) > 0 {
		add("Fremde Firewall", Warn,
			"diese Tabellen verwerfen im FORWARD-Hook und koennen die Weiterleitung blockieren: %s",
			strings.Join(foreign, ", "))
	}

	checks = append(checks, m.networkChecks(st)...)
	return checks
}

// foreignForwardDrops finds base chains of OTHER firewalls that drop in the forward hook -
// firewalld, ufw, a hand-written table. An accept in our own table does not save us from
// those: every table is evaluated for the hook and a single drop wins.
//
// What this must not report is `ip filter/FORWARD`. That is the chain Docker sets to policy
// drop, it is reached through iptables rather than a table of its own, and it is exactly
// what the "FORWARD-Policy" check above is about - including whether our accept in
// DOCKER-USER is in place. Reporting it here as well warned a second time about a case that
// is already handled, which reads as if something were wrong.
func (m *Manager) foreignForwardDrops() []string {
	res := m.run("nft", "", "-j", "list", "chains")
	if res.err != nil {
		return nil
	}
	return parseForeignForwardDrops([]byte(res.out))
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

func parseForeignForwardDrops(jsonOut []byte) []string {
	var dump struct {
		Nftables []struct {
			Chain *nftChain `json:"chain"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(jsonOut, &dump); err != nil {
		return nil
	}
	var out []string
	for _, item := range dump.Nftables {
		c := item.Chain
		if c == nil || c.Hook != "forward" || c.Policy != "drop" {
			continue
		}
		if c.Table == TableName || c.Table == GuardTableName {
			continue
		}
		if isIptablesForward(c) {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s/%s", c.Family, c.Table, c.Name))
	}
	return out
}

// isIptablesForward recognises the filter FORWARD chain that iptables-nft presents to the
// kernel - Docker's doing, and the subject of the FORWARD-Policy check.
func isIptablesForward(c *nftChain) bool {
	return (c.Family == "ip" || c.Family == "ip6") && c.Table == "filter" && c.Name == "FORWARD"
}

// offStateCheck reports whether the disabled state is really clean. Separated from the
// commands so the verdict itself is testable.
//
// The reason the off state holds is structural, not a matter of one rule catching
// everything: a packet the FRITZ!Box forwarded arrives addressed to the gateway, and only
// a DNAT rule could turn it into a packet for somewhere else. With the table gone there is
// no such rule, so the packet can only be delivered locally - where the blackhole chain
// drops it - and never reaches the forward hook at all. The three things checked here are
// what would have to be left behind for that argument to fail.
func offStateCheck(tableLoaded, acceptActive bool, flows int) Check {
	var residue []string
	if tableLoaded {
		residue = append(residue, fmt.Sprintf("die Tabelle inet %s ist noch geladen (DNAT moeglich)", TableName))
	}
	if acceptActive {
		residue = append(residue, fmt.Sprintf("die Freigabekette %s ist noch gefuellt", iptChain))
	}
	if flows > 0 {
		residue = append(residue, fmt.Sprintf("%d conntrack-Eintrag/-Eintraege auf den freigegebenen Ports", flows))
	}
	if len(residue) > 0 {
		return Check{Name: "Aus-Zustand", Level: Error,
			Message: "die Weiterleitung ist aus, aber es liegt noch etwas an: " + strings.Join(residue, "; ")}
	}
	msg := "keine DNAT-Regel, keine Forward-Freigabe, keine offenen Verbindungen - " +
		"Pakete an die freigegebenen Ports werden verworfen"
	if flows < 0 {
		return Check{Name: "Aus-Zustand", Level: Warn,
			Message: msg + " (offene Verbindungen nicht pruefbar, conntrack fehlt)"}
	}
	return Check{Name: "Aus-Zustand", Level: OK, Message: msg}
}

// guardState reports whether the blackhole table is loaded and whether it currently has
// its raw-hook chain, which is the shape it must have while the forwarding is off.
func (m *Manager) guardState() (loaded, rawDrop bool) {
	res := m.run("nft", "", "list", "table", "inet", GuardTableName)
	if res.err != nil {
		return false, false
	}
	return true, strings.Contains(res.out, "hook prerouting")
}

// guardCheck judges the blackhole table. The interesting case is the last one: a raw chain
// left over while the forwarding is on discards exactly the packets that should be
// translated, and everything else about the setup would still look correct.
func guardCheck(loaded, rawDrop, enabled bool) Check {
	const name = "Blackhole"
	switch {
	case !loaded:
		return Check{name, Warn,
			"Blackhole-Tabelle fehlt - das Gateway antwortet auf den freigegebenen Ports mit Reset statt zu schweigen"}
	case !enabled && rawDrop:
		return Check{name, OK,
			"verwirft die freigegebenen Ports vor conntrack (raw-Hook) - Pakete aus dem Internet legen keinen Zustand an"}
	case !enabled:
		return Check{name, Warn,
			"verwirft erst im input-Hook: Pakete aus dem Internet legen vorher einen conntrack-Eintrag an. " +
				"Weiterleitung einmal aus- und wieder einschalten, damit die raw-Kette geladen wird"}
	case rawDrop:
		return Check{name, Error,
			"die raw-Kette der Blackhole-Tabelle ist trotz eingeschalteter Weiterleitung geladen - " +
				"sie verwirft die Pakete vor der Uebersetzung, es kann nichts durchkommen"}
	default:
		return Check{name, OK, "verwirft die freigegebenen Ports am Gateway selbst"}
	}
}

func (m *Manager) networkChecks(st config.State) []Check {
	var checks []Check
	add := func(name string, level Level, format string, args ...any) {
		checks = append(checks, Check{Name: name, Level: level, Message: fmt.Sprintf(format, args...)})
	}

	if st.GatewayIP == "" || st.Iface == "" {
		add("Eigene Adresse", Error, "Interface oder Adresse des Gateways unbekannt - im Formular eintragen")
	} else if !addrOnInterface(st.Iface, st.GatewayIP) {
		add("Eigene Adresse", Error, "%s liegt nicht auf %s - die Portfreigabe der FRITZ!Box wuerde ins Leere zeigen",
			st.GatewayIP, st.Iface)
	} else {
		add("Eigene Adresse", OK, "%s auf %s (hierauf zeigt die Portfreigabe)", st.GatewayIP, st.Iface)
	}

	if st.Target == "" {
		add("Ziel", Warn, "keine Zieladresse gesetzt")
		return checks
	}
	if st.LANCIDR != "" {
		if _, lan, err := net.ParseCIDR(st.LANCIDR); err == nil {
			if !lan.Contains(net.ParseIP(st.Target)) {
				add("Ziel", Warn, "%s liegt ausserhalb von %s - Routing zum Ziel pruefen", st.Target, st.LANCIDR)
			}
		}
	}
	if port, ok := firstPort(st.TCPPorts); ok {
		addr := net.JoinHostPort(st.Target, strconv.Itoa(int(port)))
		conn, err := net.DialTimeout("tcp", addr, 700*time.Millisecond)
		if err != nil {
			add("Ziel erreichbar", Warn, "%s antwortet nicht (%v) - laeuft Sunshine?", addr, rootErr(err))
		} else {
			conn.Close()
			add("Ziel erreichbar", OK, "%s antwortet", addr)
		}
	}
	return checks
}

func firstPort(ranges []config.PortRange) (uint16, bool) {
	if len(ranges) == 0 {
		return 0, false
	}
	return ranges[0].From, true
}

func rootErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		return msg[i+2:]
	}
	return msg
}

func addrOnInterface(iface, want string) bool {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.String() == want {
			return true
		}
	}
	return false
}

// ConntrackAccounting reports whether the kernel counts bytes per connection. Costs two
// counter increments per packet in a code path conntrack walks anyway, which is why it is
// the cheapest way to get per-client volumes - no rule, no userspace, no copy.
func ConntrackAccounting() bool {
	v, err := readSysctl("net/netfilter/nf_conntrack_acct")
	return err == nil && v == "1"
}

func readSysctl(path string) (string, error) {
	b, err := os.ReadFile("/proc/sys/" + path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// WorstLevel reduces the checks to the most severe verdict among them.
func WorstLevel(checks []Check) Level {
	worst := OK
	for _, c := range checks {
		if c.Level == Error {
			return Error
		}
		if c.Level == Warn {
			worst = Warn
		}
	}
	return worst
}
