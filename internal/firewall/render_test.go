package firewall

import (
	"strings"
	"testing"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
)

func testState() config.State {
	st := config.Defaults()
	st.Target = "10.10.10.5"
	st.GatewayIP = "10.10.10.20"
	st.LANCIDR = "10.10.10.0/24"
	st.Iface = "eth0"
	st.Enabled = true
	return st
}

func TestRenderForward(t *testing.T) {
	out, err := RenderForward(testState())
	if err != nil {
		t.Fatalf("RenderForward: %v", err)
	}
	// Idempotent, atomic replacement: create-if-missing, delete, then define anew.
	if !strings.HasPrefix(out, "table inet sunshine_gw\ndelete table inet sunshine_gw\n") {
		t.Errorf("Ruleset beginnt nicht mit dem delete-Idiom:\n%s", out)
	}
	want := []string{
		"type nat hook prerouting priority dstnat",
		"ip daddr 10.10.10.20 ip saddr != 10.10.10.0/24 tcp dport @tcp_ports counter dnat ip to 10.10.10.5",
		"ip daddr 10.10.10.20 ip saddr != 10.10.10.0/24 udp dport @udp_ports counter dnat ip to 10.10.10.5",
		"ip daddr 10.10.10.5 ct status dnat tcp dport @tcp_ports counter masquerade",
		"elements = { 47984, 47989, 48010 }",
		"elements = { 47998-48000, 48002 }",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("Ruleset enthaelt %q nicht:\n%s", w, out)
		}
	}
	if strings.Contains(out, "flowtable") {
		t.Error("Fast-Path war nicht eingeschaltet, taucht aber im Ruleset auf")
	}
}

func TestRenderForwardWithoutExternalOnly(t *testing.T) {
	st := testState()
	st.ExternalOnly = false
	out, err := RenderForward(st)
	if err != nil {
		t.Fatalf("RenderForward: %v", err)
	}
	if strings.Contains(out, "ip saddr !=") {
		t.Errorf("Quell-Einschraenkung trotz ExternalOnly=false:\n%s", out)
	}
}

func TestRenderForwardFlowtable(t *testing.T) {
	st := testState()
	st.Flowtable = true
	out, err := RenderForward(st)
	if err != nil {
		t.Fatalf("RenderForward: %v", err)
	}
	if !strings.Contains(out, "devices = { eth0 }") || !strings.Contains(out, "flow add @fastpath") {
		t.Errorf("Fast-Path unvollstaendig:\n%s", out)
	}
	// The flowtable has to be declared before the rule that references it.
	if strings.Index(out, "flowtable fastpath") > strings.Index(out, "flow add @fastpath") {
		t.Error("flowtable wird vor ihrer Deklaration verwendet")
	}
}

func TestRenderForwardNeedsTargetAndGateway(t *testing.T) {
	st := testState()
	st.Target = ""
	if _, err := RenderForward(st); err == nil {
		t.Error("Ruleset ohne Ziel wurde erzeugt")
	}
	st = testState()
	st.GatewayIP = ""
	if _, err := RenderForward(st); err == nil {
		t.Error("Ruleset ohne eigene Adresse wurde erzeugt")
	}
}

// The blackhole table must not depend on the target: it stays loaded while the
// forwarding is off, which is what keeps the permanent FRITZ!Box rule harmless.
func TestRenderGuard(t *testing.T) {
	st := testState()
	st.Target = ""
	out, err := RenderGuard(st)
	if err != nil {
		t.Fatalf("RenderGuard: %v", err)
	}
	for _, w := range []string{
		"table inet sunshine_gw_guard",
		"type filter hook input priority filter - 10",
		"tcp dport @tcp_ports counter drop",
		"udp dport @udp_ports counter drop",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("Blackhole-Tabelle enthaelt %q nicht:\n%s", w, out)
		}
	}
}

func TestForwardRulesCoverBothDirections(t *testing.T) {
	rules := forwardRules(testState())
	if len(rules) != 3 {
		t.Fatalf("%d Regeln, erwartet 3 (TCP, UDP, Rueckrichtung)", len(rules))
	}
	joined := ""
	for _, r := range rules {
		joined += strings.Join(r, " ") + "\n"
	}
	for _, w := range []string{
		"-p tcp -d 10.10.10.5 -m multiport --dports 47984,47989,48010 -j ACCEPT",
		"-p udp -d 10.10.10.5 -m multiport --dports 47998:48000,48002 -j ACCEPT",
		"-s 10.10.10.5 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("Forward-Freigabe enthaelt %q nicht:\n%s", w, joined)
		}
	}
}

func TestParseDeleted(t *testing.T) {
	n, ok := parseDeleted("conntrack v1.4.8 (conntrack-tools): 3 flow entries have been deleted.")
	if !ok || n != 3 {
		t.Errorf("parseDeleted = %d, %v; want 3, true", n, ok)
	}
	if n, ok := parseDeleted("irgendwas anderes"); ok || n != 0 {
		t.Errorf("parseDeleted = %d, %v; want 0, false", n, ok)
	}
}

// Docker sets the iptables filter FORWARD chain to policy drop, and iptables-nft makes it
// visible as `ip filter/FORWARD`. That case belongs to the FORWARD-Policy check, which also
// knows whether our accept in DOCKER-USER is in place - reporting it here too warned twice
// about one already handled situation. A real third-party firewall must still be reported.
func TestParseForeignForwardDrops(t *testing.T) {
	const chains = `{"nftables":[
	{"metainfo":{"version":"1.1.1","json_schema_version":1}},
	{"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
	{"chain":{"family":"ip6","table":"filter","name":"FORWARD","handle":3,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
	{"chain":{"family":"ip","table":"filter","name":"DOCKER-USER","handle":6}},
	{"chain":{"family":"ip","table":"filter","name":"SUNSHINE-GW","handle":7}},
	{"chain":{"family":"inet","table":"sunshine_gw","name":"forward","handle":4,"type":"filter","hook":"forward","prio":-10,"policy":"accept"}},
	{"chain":{"family":"inet","table":"sunshine_gw_guard","name":"input","handle":5,"type":"filter","hook":"input","prio":-10,"policy":"accept"}},
	{"chain":{"family":"inet","table":"firewalld","name":"filter_FORWARD","handle":8,"type":"filter","hook":"forward","prio":10,"policy":"drop"}},
	{"chain":{"family":"inet","table":"eigenbau","name":"fwd","handle":9,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
	{"chain":{"family":"inet","table":"eigenbau","name":"in","handle":10,"type":"filter","hook":"input","prio":0,"policy":"drop"}}
	]}`

	got := parseForeignForwardDrops([]byte(chains))
	want := []string{"inet firewalld/filter_FORWARD"}
	if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
		t.Errorf("parseForeignForwardDrops = %v, want %v", got, want)
	}
}

func TestParseForeignForwardDropsSurvivesGarbage(t *testing.T) {
	if got := parseForeignForwardDrops([]byte("kein JSON")); got != nil {
		t.Errorf("= %v, want nil", got)
	}
	if got := parseForeignForwardDrops([]byte(`{"nftables":[]}`)); got != nil {
		t.Errorf("= %v, want nil", got)
	}
}
