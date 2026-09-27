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

// The off state is the security promise of the whole gateway, so it is stated as a fact in
// the UI. This is the verdict behind that statement.
func TestOffStateCheck(t *testing.T) {
	clean := offStateCheck(false, false, 0)
	if clean.Level != OK {
		t.Errorf("sauberer Aus-Zustand = %s: %s", clean.Level, clean.Message)
	}
	if !strings.Contains(clean.Message, "verworfen") {
		t.Errorf("Meldung sagt nicht, was passiert: %q", clean.Message)
	}

	// Jede einzelne Hinterlassenschaft muss auffallen - und benannt werden.
	for _, tc := range []struct {
		name         string
		tableLoaded  bool
		acceptActive bool
		flows        int
		wantIn       string
	}{
		{"Tabelle geladen", true, false, 0, "noch geladen"},
		{"Freigabekette gefuellt", false, true, 0, "SUNSHINE-GW"},
		{"offene Verbindung", false, false, 3, "3 conntrack"},
	} {
		got := offStateCheck(tc.tableLoaded, tc.acceptActive, tc.flows)
		if got.Level != Error {
			t.Errorf("%s: Level = %s, erwartet error", tc.name, got.Level)
		}
		if !strings.Contains(got.Message, tc.wantIn) {
			t.Errorf("%s: Meldung nennt %q nicht: %s", tc.name, tc.wantIn, got.Message)
		}
	}

	// Alles zusammen wird auch zusammen gemeldet, nicht nur das erste.
	all := offStateCheck(true, true, 2)
	for _, want := range []string{"noch geladen", "SUNSHINE-GW", "2 conntrack"} {
		if !strings.Contains(all.Message, want) {
			t.Errorf("Sammelmeldung ohne %q: %s", want, all.Message)
		}
	}

	// conntrack nicht installiert: der Rest gilt weiter, aber die Aussage wird abgeschwaecht.
	unknown := offStateCheck(false, false, -1)
	if unknown.Level != Warn || !strings.Contains(unknown.Message, "conntrack fehlt") {
		t.Errorf("unbekannte Flows = %s: %s", unknown.Level, unknown.Message)
	}
}

// While the forwarding is off the blackhole has to discard ahead of conntrack. The input
// hook runs after it, so a packet dropped there has already cost a conntrack entry - and
// with the FRITZ!Box rule standing permanently, anyone could allocate those at will.
func TestGuardDropsBeforeConntrackWhileOff(t *testing.T) {
	st := testState()
	st.Enabled = false
	out, err := RenderGuard(st)
	if err != nil {
		t.Fatalf("RenderGuard: %v", err)
	}
	if !strings.Contains(out, "type filter hook prerouting priority raw") {
		t.Errorf("keine Kette im raw-Hook:\n%s", out)
	}
	for _, want := range []string{
		"ip daddr 10.10.10.20 tcp dport @tcp_ports counter drop",
		"ip daddr 10.10.10.20 udp dport @udp_ports counter drop",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Ruleset enthaelt %q nicht:\n%s", want, out)
		}
	}
	// Der input-Hook bleibt als zweite Schicht stehen.
	if !strings.Contains(out, "type filter hook input priority filter - 10") {
		t.Errorf("input-Hook fehlt in der Aus-Variante:\n%s", out)
	}
	if strings.Index(out, "hook prerouting") > strings.Index(out, "hook input") {
		t.Error("raw-Kette muss vor der input-Kette definiert werden")
	}
}

// Mit eingeschalteter Weiterleitung darf diese Kette nicht existieren: raw laeuft vor
// dstnat und wuerde genau die Pakete verwerfen, die uebersetzt werden sollen.
func TestGuardHasNoRawChainWhileOn(t *testing.T) {
	st := testState() // Enabled = true
	out, err := RenderGuard(st)
	if err != nil {
		t.Fatalf("RenderGuard: %v", err)
	}
	if strings.Contains(out, "hook prerouting") {
		t.Errorf("raw-Kette wuerde die Weiterleitung abwuergen:\n%s", out)
	}
	if !strings.Contains(out, "hook input") {
		t.Errorf("input-Hook fehlt:\n%s", out)
	}
}

// Ohne bekannte eigene Adresse gibt es kein Kriterium fuer die raw-Regel; dann bleibt es
// bei der input-Schicht, statt etwas Falsches zu verwerfen.
func TestGuardWithoutGatewayAddressSkipsRawChain(t *testing.T) {
	st := testState()
	st.Enabled = false
	st.GatewayIP = ""
	out, err := RenderGuard(st)
	if err != nil {
		t.Fatalf("RenderGuard: %v", err)
	}
	if strings.Contains(out, "hook prerouting") {
		t.Errorf("raw-Kette ohne Gateway-Adresse:\n%s", out)
	}
	if !strings.Contains(out, "hook input") {
		t.Errorf("input-Hook fehlt:\n%s", out)
	}
}

func TestGuardCheck(t *testing.T) {
	cases := []struct {
		name            string
		loaded, raw, on bool
		want            Level
		wantIn          string
	}{
		{"aus, verwirft vor conntrack", true, true, false, OK, "vor conntrack"},
		{"aus, nur input-Hook", true, false, false, Warn, "conntrack-Eintrag"},
		{"an, ohne raw-Kette", true, false, true, OK, "am Gateway selbst"},
		// Bliebe die raw-Kette beim Einschalten stehen, waere alles andere gruen und
		// nichts wuerde durchkommen - das muss auffallen.
		{"an, raw-Kette liegengeblieben", true, true, true, Error, "es kann nichts durchkommen"},
		{"Tabelle fehlt", false, false, false, Warn, "fehlt"},
	}
	for _, tc := range cases {
		got := guardCheck(tc.loaded, tc.raw, tc.on)
		if got.Level != tc.want {
			t.Errorf("%s: Level = %s, erwartet %s (%s)", tc.name, got.Level, tc.want, got.Message)
		}
		if !strings.Contains(got.Message, tc.wantIn) {
			t.Errorf("%s: Meldung nennt %q nicht: %s", tc.name, tc.wantIn, got.Message)
		}
	}
}

// "Exclusively to the configured address" has to be stated by this gateway's own rules.
// Without these two, a Sunshine port routed onwards to another host would only be stopped
// by Docker's FORWARD policy - a default of a different component.
func TestForwardChainDropsStrayDestinations(t *testing.T) {
	out, err := RenderForward(testState())
	if err != nil {
		t.Fatalf("RenderForward: %v", err)
	}
	for _, want := range []string{
		"ip daddr != 10.10.10.5 tcp dport @tcp_ports counter drop",
		"ip daddr != 10.10.10.5 udp dport @udp_ports counter drop",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Ruleset enthaelt %q nicht:\n%s", want, out)
		}
	}
}

// Die Reihenfolge ist hier keine Kosmetik: der Ephemeral-Port-Bereich (32768-60999)
// enthaelt 47984-48010. Waehlt ein Client 47998 als Quellport, traegt die Antwort an ihn
// dport=47998 - stuende die Verwerfen-Regel vor dem accept fuer die Rueckrichtung, wuerde
// genau diese Antwort weggeworfen und der Stream des Clients bliebe haengen.
func TestStrayDropComesAfterReplyAccept(t *testing.T) {
	out, err := RenderForward(testState())
	if err != nil {
		t.Fatalf("RenderForward: %v", err)
	}
	reply := strings.Index(out, LabelFwdReply)
	strayTCP := strings.Index(out, LabelStrayTCP)
	strayUDP := strings.Index(out, LabelStrayUDP)
	if reply < 0 || strayTCP < 0 || strayUDP < 0 {
		t.Fatalf("Regeln fehlen:\n%s", out)
	}
	if reply > strayTCP || reply > strayUDP {
		t.Error("accept fuer die Rueckrichtung muss vor den Verwerfen-Regeln stehen")
	}
	// Und die Hinrichtung muss vor beiden akzeptiert werden.
	if fwd := strings.Index(out, LabelFwdUDP); fwd < 0 || fwd > strayUDP {
		t.Error("accept fuer die Hinrichtung muss vor den Verwerfen-Regeln stehen")
	}
}
