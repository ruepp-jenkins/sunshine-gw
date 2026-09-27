package firewall

import (
	"strings"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
)

// Docker sets the iptables FORWARD policy to DROP. An accept in our own nftables
// table does not undo that: every table's chain is evaluated for the hook, and a DROP
// in any of them wins. The reliable integration point is DOCKER-USER, which Docker
// jumps to from FORWARD before its own chains - an ACCEPT there ends the traversal of
// the filter table for that packet.
//
// We keep our rules in a child chain so enabling and disabling is a flush, never a
// hunt for individual rules.
const iptChain = "SUNSHINE-GW"

const dockerUserChain = "DOCKER-USER"

// DockerUserPresent reports whether Docker's iptables integration is active.
func (m *Manager) DockerUserPresent() bool {
	if !has("iptables") {
		return false
	}
	return m.run("iptables", "", "-w", "5", "-n", "-L", dockerUserChain).err == nil
}

// ForwardPolicyDrop reports whether the filter FORWARD policy drops by default.
func (m *Manager) ForwardPolicyDrop() bool {
	res := m.run("iptables", "", "-w", "5", "-n", "-L", "FORWARD")
	if res.err != nil {
		return false
	}
	first := res.out
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	return strings.Contains(first, "policy DROP")
}

func (m *Manager) ensureForwardAccept(st config.State) error {
	if !m.DockerUserPresent() {
		return nil
	}
	// Create the chain if needed; an existing chain is not an error.
	if res := m.run("iptables", "", "-w", "5", "-N", iptChain); res.err != nil &&
		!strings.Contains(res.out, "already exists") {
		return res.err
	}
	if res := m.run("iptables", "", "-w", "5", "-F", iptChain); res.err != nil {
		return res.err
	}
	for _, r := range forwardRules(st) {
		args := append([]string{"-w", "5", "-A", iptChain}, r...)
		if res := m.run("iptables", "", args...); res.err != nil {
			return res.err
		}
	}
	// Jump from DOCKER-USER, exactly once, as the first rule.
	if res := m.run("iptables", "", "-w", "5", "-C", dockerUserChain, "-j", iptChain); res.err != nil {
		if res := m.run("iptables", "", "-w", "5", "-I", dockerUserChain, "1", "-j", iptChain); res.err != nil {
			return res.err
		}
	}
	return nil
}

// clearForwardAccept empties the chain but leaves it and the jump in place: an empty
// chain simply returns, and not touching the jump avoids churn in Docker's chains.
func (m *Manager) clearForwardAccept() error {
	if !m.DockerUserPresent() {
		return nil
	}
	if res := m.run("iptables", "", "-w", "5", "-n", "-L", iptChain); res.err != nil {
		return nil // chain does not exist, nothing to clear
	}
	return m.run("iptables", "", "-w", "5", "-F", iptChain).err
}

// ForwardAcceptActive reports whether our accept rules are currently installed.
func (m *Manager) ForwardAcceptActive() bool {
	if !m.DockerUserPresent() {
		return false
	}
	res := m.run("iptables", "", "-w", "5", "-S", iptChain)
	if res.err != nil {
		return false
	}
	return strings.Contains(res.out, "-A "+iptChain)
}

func forwardRules(st config.State) [][]string {
	var rules [][]string
	if len(st.TCPPorts) > 0 {
		rules = append(rules, []string{"-p", "tcp", "-d", st.Target,
			"-m", "multiport", "--dports", config.MultiportSpec(st.TCPPorts), "-j", "ACCEPT"})
	}
	if len(st.UDPPorts) > 0 {
		rules = append(rules, []string{"-p", "udp", "-d", st.Target,
			"-m", "multiport", "--dports", config.MultiportSpec(st.UDPPorts), "-j", "ACCEPT"})
	}
	rules = append(rules, []string{"-s", st.Target,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"})
	return rules
}
