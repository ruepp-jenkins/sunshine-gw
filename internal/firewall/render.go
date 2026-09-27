package firewall

import (
	"fmt"
	"strings"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
)

// Rule comments double as stable labels for the counters shown in the web UI.
const (
	LabelDNATTCP  = "dnat-tcp"
	LabelDNATUDP  = "dnat-udp"
	LabelMasqTCP  = "masq-tcp"
	LabelMasqUDP  = "masq-udp"
	LabelFwdTCP   = "fwd-tcp"
	LabelFwdUDP   = "fwd-udp"
	LabelFwdReply = "fwd-reply"
	LabelGuardTCP = "guard-tcp"
	LabelGuardUDP = "guard-udp"
)

// RenderDelete produces an idempotent, atomic removal of a table: the bare `table`
// line creates it if it is absent, so the `delete` can never fail.
func RenderDelete(name string) string {
	return fmt.Sprintf("table inet %s\ndelete table inet %s\n", name, name)
}

func portSet(name string, ranges []config.PortRange) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\tset %s {\n", name)
	b.WriteString("\t\ttype inet_service\n")
	b.WriteString("\t\tflags interval\n")
	fmt.Fprintf(&b, "\t\telements = { %s }\n", config.NftElements(ranges))
	b.WriteString("\t}\n")
	return b.String()
}

// RenderForward builds the NAT and forward ruleset. Only the first packet of a flow
// walks these chains; afterwards conntrack handles the translation in the fast path.
func RenderForward(st config.State) (string, error) {
	if st.Target == "" {
		return "", fmt.Errorf("keine Zieladresse gesetzt")
	}
	if st.GatewayIP == "" {
		return "", fmt.Errorf("eigene Gateway-Adresse unbekannt")
	}
	tcp, udp := len(st.TCPPorts) > 0, len(st.UDPPorts) > 0

	// The FRITZ!Box only rewrites the destination, so the source address of a
	// forwarded packet is still the real internet client. That makes it possible to
	// serve only external sources and leave LAN clients on the direct path.
	src := ""
	if st.ExternalOnly && st.LANCIDR != "" {
		src = fmt.Sprintf("ip saddr != %s ", st.LANCIDR)
	}

	var b strings.Builder
	b.WriteString(RenderDelete(TableName))
	b.WriteString("\n")
	fmt.Fprintf(&b, "table inet %s {\n", TableName)

	if st.Flowtable && st.Iface != "" {
		// Software fast path: established flows bypass the netfilter chains entirely.
		fmt.Fprintf(&b, "\tflowtable fastpath {\n\t\thook ingress priority filter\n\t\tdevices = { %s }\n\t}\n", st.Iface)
	}
	if tcp {
		b.WriteString(portSet("tcp_ports", st.TCPPorts))
	}
	if udp {
		b.WriteString(portSet("udp_ports", st.UDPPorts))
	}

	// Destination NAT: packets addressed to the gateway itself are the ones the
	// FRITZ!Box forwarded. No WAN interface exists here to match on.
	b.WriteString("\n\tchain prerouting {\n")
	b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	if tcp {
		fmt.Fprintf(&b, "\t\tip daddr %s %stcp dport @tcp_ports counter dnat ip to %s comment \"%s\"\n",
			st.GatewayIP, src, st.Target, LabelDNATTCP)
	}
	if udp {
		fmt.Fprintf(&b, "\t\tip daddr %s %sudp dport @udp_ports counter dnat ip to %s comment \"%s\"\n",
			st.GatewayIP, src, st.Target, LabelDNATUDP)
	}
	b.WriteString("\t}\n")

	// Source NAT is required because the Sunshine host routes its replies to the
	// FRITZ!Box, not back to us. `ct status dnat` limits it to flows we translated.
	b.WriteString("\n\tchain postrouting {\n")
	b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	if tcp {
		fmt.Fprintf(&b, "\t\tip daddr %s ct status dnat tcp dport @tcp_ports counter masquerade comment \"%s\"\n",
			st.Target, LabelMasqTCP)
	}
	if udp {
		fmt.Fprintf(&b, "\t\tip daddr %s ct status dnat udp dport @udp_ports counter masquerade comment \"%s\"\n",
			st.Target, LabelMasqUDP)
	}
	b.WriteString("\t}\n")

	// The forward chain accepts explicitly (and counts, which is what the UI shows).
	// Its policy stays accept so it never interferes with other tables on the host.
	b.WriteString("\n\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority filter - 10; policy accept;\n")
	if st.Flowtable && st.Iface != "" {
		fmt.Fprintf(&b, "\t\tip daddr %s ct state established flow add @fastpath\n", st.Target)
	}
	if tcp {
		fmt.Fprintf(&b, "\t\tip daddr %s tcp dport @tcp_ports counter accept comment \"%s\"\n",
			st.Target, LabelFwdTCP)
	}
	if udp {
		fmt.Fprintf(&b, "\t\tip daddr %s udp dport @udp_ports counter accept comment \"%s\"\n",
			st.Target, LabelFwdUDP)
	}
	// Labelled like the others: this counter is the download direction of everything the
	// gateway forwards, which is what the bandwidth graph in the UI draws.
	fmt.Fprintf(&b, "\t\tip saddr %s ct state established,related counter accept comment \"%s\"\n",
		st.Target, LabelFwdReply)
	b.WriteString("\t}\n")

	b.WriteString("}\n")
	return b.String(), nil
}

// RenderGuard builds the table that drops the forwarded ports on the gateway itself.
// It stays loaded even when forwarding is off: the gateway then answers with nothing
// at all instead of a reset, so the permanent FRITZ!Box rule looks like a blackhole
// from outside. Enabled forwarding is unaffected, because DNAT in prerouting sends
// those packets to the forward hook, never to input.
func RenderGuard(st config.State) (string, error) {
	tcp, udp := len(st.TCPPorts) > 0, len(st.UDPPorts) > 0
	if !tcp && !udp {
		return "", fmt.Errorf("keine Ports konfiguriert")
	}
	var b strings.Builder
	b.WriteString(RenderDelete(GuardTableName))
	b.WriteString("\n")
	fmt.Fprintf(&b, "table inet %s {\n", GuardTableName)
	if tcp {
		b.WriteString(portSet("tcp_ports", st.TCPPorts))
	}
	if udp {
		b.WriteString(portSet("udp_ports", st.UDPPorts))
	}
	b.WriteString("\n\tchain input {\n")
	b.WriteString("\t\ttype filter hook input priority filter - 10; policy accept;\n")
	if tcp {
		fmt.Fprintf(&b, "\t\ttcp dport @tcp_ports counter drop comment \"%s\"\n", LabelGuardTCP)
	}
	if udp {
		fmt.Fprintf(&b, "\t\tudp dport @udp_ports counter drop comment \"%s\"\n", LabelGuardUDP)
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}
