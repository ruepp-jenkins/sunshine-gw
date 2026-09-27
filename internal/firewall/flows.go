package firewall

import (
	"strconv"
	"strings"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
)

// Flow is one forwarded connection as conntrack sees it. Nothing here costs anything in
// the data path: the kernel keeps these entries anyway to do the translation, so reading
// them is a dump of state that already exists.
type Flow struct {
	Proto      string `json:"proto"`
	ClientIP   string `json:"clientIP"`
	ClientPort int    `json:"clientPort"`
	Port       int    `json:"port"`
	// BytesUp counts client -> Sunshine, BytesDown the reply direction. Both are only
	// filled when conntrack accounting is switched on; Accounted says whether they are.
	BytesUp   uint64 `json:"bytesUp"`
	BytesDown uint64 `json:"bytesDown"`
	Accounted bool   `json:"accounted"`
	Unreplied bool   `json:"unreplied"`
}

// Key identifies a flow across samples, so byte counters can be turned into deltas.
func (f Flow) Key() string {
	return f.Proto + "/" + f.ClientIP + ":" + strconv.Itoa(f.ClientPort) + "->" + strconv.Itoa(f.Port)
}

// Flows lists the forwarded connections. The selector is the gateway's own address,
// because that is the ORIGINAL destination of anything the FRITZ!Box sent here; the reply
// tuple carries the Sunshine host instead.
func (m *Manager) Flows(st config.State) ([]Flow, error) {
	if !has("conntrack") || st.GatewayIP == "" {
		return nil, nil
	}
	res := m.run("conntrack", "", "-L", "-d", st.GatewayIP)
	if res.err != nil && res.out == "" {
		return nil, res.err
	}
	return parseFlows(res.out, watchedPorts(st)), nil
}

func watchedPorts(st config.State) map[string]bool {
	watched := map[string]bool{}
	for _, p := range config.ExpandPorts(st.TCPPorts) {
		watched["tcp/"+strconv.Itoa(int(p))] = true
	}
	for _, p := range config.ExpandPorts(st.UDPPorts) {
		watched["udp/"+strconv.Itoa(int(p))] = true
	}
	return watched
}

// parseFlows reads `conntrack -L` output. The format puts the original tuple first and the
// reply tuple second, each optionally followed by packets=/bytes= when accounting is on:
//
//	udp 17 29 src=203.0.113.9 dst=10.10.10.20 sport=51234 dport=47998 packets=120 bytes=140000 \
//	          src=10.10.10.5 dst=10.10.10.20 sport=47998 dport=51234 packets=110 bytes=120000 [ASSURED]
//
// Parsed by walking the key=value tokens rather than by position: TCP lines carry a state
// word the UDP ones do not, and the tool's own summary line is simply skipped because it
// has no src= at all.
func parseFlows(out string, watched map[string]bool) []Flow {
	var flows []Flow
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		flow := Flow{Proto: proto}
		dir := 0
		for _, f := range fields[1:] {
			if f == "[UNREPLIED]" {
				flow.Unreplied = true
				continue
			}
			key, value, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			switch key {
			case "src":
				// The second src= starts the reply tuple.
				if flow.ClientIP == "" {
					flow.ClientIP = value
				} else {
					dir = 1
				}
			case "sport":
				if dir == 0 && flow.ClientPort == 0 {
					flow.ClientPort = atoi(value)
				}
			case "dport":
				if dir == 0 && flow.Port == 0 {
					flow.Port = atoi(value)
				}
			case "bytes":
				n, err := strconv.ParseUint(value, 10, 64)
				if err != nil {
					continue
				}
				flow.Accounted = true
				if dir == 0 {
					flow.BytesUp = n
				} else {
					flow.BytesDown = n
				}
			}
		}
		if flow.ClientIP == "" || flow.Port == 0 {
			continue
		}
		if len(watched) > 0 && !watched[proto+"/"+strconv.Itoa(flow.Port)] {
			continue
		}
		flows = append(flows, flow)
	}
	return flows
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// ActiveFlows counts the forwarded connections, or -1 when conntrack cannot be asked.
func (m *Manager) ActiveFlows(st config.State) int {
	if !has("conntrack") || st.GatewayIP == "" {
		return -1
	}
	flows, err := m.Flows(st)
	if err != nil {
		return -1
	}
	return len(flows)
}
