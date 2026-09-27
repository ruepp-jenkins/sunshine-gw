package firewall

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/stefan/sunshine-gateway/internal/config"
)

var deletedRe = regexp.MustCompile(`(\d+) flow entries have been deleted`)

// FlushConntrack removes the conntrack entries of the forwarded flows. Deleting the
// nftables table alone does not stop an established stream: its translation lives in
// conntrack and would keep working until the entry times out. This is what makes the
// off switch immediate.
//
// The selector is the ORIGINAL destination, which for a forwarded flow is the gateway
// itself - not the Sunshine host. Matching per port matters: `-d <gateway>` without a
// port would also tear down unrelated connections to this machine, such as SSH.
func (m *Manager) FlushConntrack(st config.State) (int, error) {
	if st.GatewayIP == "" {
		return 0, fmt.Errorf("eigene Gateway-Adresse unbekannt")
	}
	if !has("conntrack") {
		return 0, fmt.Errorf("conntrack nicht installiert - laufende Streams laufen bis zum Timeout weiter")
	}
	total := 0
	var errs []string
	for _, spec := range []struct {
		proto string
		ports []config.PortRange
	}{{"tcp", st.TCPPorts}, {"udp", st.UDPPorts}} {
		for _, port := range config.ExpandPorts(spec.ports) {
			res := m.run("conntrack", "", "-D", "-d", st.GatewayIP,
				"-p", spec.proto, "--dport", strconv.Itoa(int(port)))
			n, matched := parseDeleted(res.out)
			total += n
			// Exit status 1 with no match is the normal "nothing to delete" case.
			if res.err != nil && !matched && !strings.Contains(res.out, "0 flow entries") {
				errs = append(errs, fmt.Sprintf("%s/%d: %v", spec.proto, port, res.err))
			}
		}
	}
	if len(errs) > 0 {
		return total, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return total, nil
}

func parseDeleted(out string) (int, bool) {
	match := deletedRe.FindStringSubmatch(out)
	if match == nil {
		return 0, false
	}
	n, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// ActiveFlows counts the conntrack entries currently belonging to forwarded flows,
// so the UI can show that a stream is really running.
func (m *Manager) ActiveFlows(st config.State) int {
	if !has("conntrack") || st.GatewayIP == "" {
		return -1
	}
	res := m.run("conntrack", "", "-L", "-d", st.GatewayIP)
	if res.err != nil && res.out == "" {
		return -1
	}
	watched := map[string]bool{}
	for _, p := range config.ExpandPorts(st.TCPPorts) {
		watched["tcp/"+strconv.Itoa(int(p))] = true
	}
	for _, p := range config.ExpandPorts(st.UDPPorts) {
		watched["udp/"+strconv.Itoa(int(p))] = true
	}
	count := 0
	for _, line := range strings.Split(res.out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		proto := fields[0]
		for _, f := range fields {
			if !strings.HasPrefix(f, "dport=") {
				continue
			}
			if watched[proto+"/"+strings.TrimPrefix(f, "dport=")] {
				count++
			}
			break
		}
	}
	return count
}
