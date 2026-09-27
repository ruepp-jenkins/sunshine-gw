package firewall

import "testing"

// Real `conntrack -L` output: a UDP video flow with accounting on, a TCP flow with its
// state word, an unreplied one, a flow on a port we do not forward, and the tool's own
// summary line on stderr.
const conntrackSample = `udp      17 28 src=203.0.113.9 dst=10.10.10.20 sport=51234 dport=47998 packets=1200 bytes=1680000 src=10.10.10.5 dst=10.10.10.20 sport=47998 dport=51234 packets=900 bytes=76000 [ASSURED] mark=0 use=1
tcp      6 431996 ESTABLISHED src=203.0.113.9 dst=10.10.10.20 sport=44001 dport=47989 packets=42 bytes=5800 src=10.10.10.5 dst=10.10.10.20 sport=47989 dport=44001 packets=40 bytes=9100 [ASSURED] mark=0 use=1
udp      17 15 src=198.51.100.7 dst=10.10.10.20 sport=60000 dport=48000 packets=3 bytes=210 [UNREPLIED] src=10.10.10.5 dst=10.10.10.20 sport=48000 dport=60000 packets=0 bytes=0 mark=0 use=1
tcp      6 86399 ESTABLISHED src=10.10.10.99 dst=10.10.10.20 sport=55000 dport=22 packets=10 bytes=900 src=10.10.10.20 dst=10.10.10.99 sport=22 dport=55000 packets=8 bytes=800 [ASSURED] mark=0 use=1
conntrack v1.4.8 (conntrack-tools): 4 flow entries have been shown.`

func TestParseFlows(t *testing.T) {
	watched := map[string]bool{"udp/47998": true, "udp/48000": true, "tcp/47989": true}
	flows := parseFlows(conntrackSample, watched)
	if len(flows) != 3 {
		t.Fatalf("%d Flows, erwartet 3 (die SSH-Verbindung auf Port 22 gehoert nicht dazu): %+v", len(flows), flows)
	}

	video := flows[0]
	if video.Proto != "udp" || video.ClientIP != "203.0.113.9" || video.ClientPort != 51234 || video.Port != 47998 {
		t.Errorf("Video-Flow falsch gelesen: %+v", video)
	}
	// Up is client -> Sunshine, down the reply. Bei Game-Streaming ist down das Vielfache
	// von up; eine Verwechslung waere in der Grafik sofort sichtbar, hier auch.
	if video.BytesUp != 1680000 || video.BytesDown != 76000 {
		t.Errorf("Byte-Richtungen falsch: up=%d down=%d", video.BytesUp, video.BytesDown)
	}
	if !video.Accounted {
		t.Error("Accounting wurde nicht erkannt, obwohl bytes= vorhanden ist")
	}
	if video.Unreplied {
		t.Error("Flow faelschlich als unreplied markiert")
	}

	if flows[1].Proto != "tcp" || flows[1].Port != 47989 || flows[1].BytesDown != 9100 {
		t.Errorf("TCP-Flow falsch gelesen (Status-Wort in der Zeile): %+v", flows[1])
	}
	if !flows[2].Unreplied || flows[2].ClientIP != "198.51.100.7" {
		t.Errorf("unreplied-Flow falsch gelesen: %+v", flows[2])
	}
	if got, want := flows[0].Key(), "udp/203.0.113.9:51234->47998"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
}

// Without net.netfilter.nf_conntrack_acct the byte counters are absent. Client addresses
// and flow counts must still work; only the volumes are unknown.
func TestParseFlowsWithoutAccounting(t *testing.T) {
	const noAcct = `udp      17 28 src=203.0.113.9 dst=10.10.10.20 sport=51234 dport=47998 src=10.10.10.5 dst=10.10.10.20 sport=47998 dport=51234 [ASSURED] mark=0 use=1`
	flows := parseFlows(noAcct, map[string]bool{"udp/47998": true})
	if len(flows) != 1 {
		t.Fatalf("%d Flows, erwartet 1", len(flows))
	}
	if flows[0].Accounted || flows[0].BytesUp != 0 {
		t.Errorf("ohne Accounting darf nichts gezaehlt werden: %+v", flows[0])
	}
	if flows[0].ClientIP != "203.0.113.9" {
		t.Errorf("Client-Adresse fehlt: %+v", flows[0])
	}
}

func TestParseFlowsIgnoresGarbage(t *testing.T) {
	if got := parseFlows("", nil); got != nil {
		t.Errorf("= %+v, want nil", got)
	}
	if got := parseFlows("irgendwas\nkaputtes", nil); got != nil {
		t.Errorf("= %+v, want nil", got)
	}
	// Ohne Portfilter darf nichts verworfen werden.
	if got := parseFlows(conntrackSample, nil); len(got) != 4 {
		t.Errorf("%d Flows ohne Portfilter, erwartet 4", len(got))
	}
}
