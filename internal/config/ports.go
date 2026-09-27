package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of ports. A single port has From == To.
type PortRange struct {
	From uint16
	To   uint16
}

func (p PortRange) String() string {
	if p.From == p.To {
		return strconv.Itoa(int(p.From))
	}
	return fmt.Sprintf("%d-%d", p.From, p.To)
}

// Ports expands the range into individual port numbers.
func (p PortRange) Ports() []uint16 {
	out := make([]uint16, 0, int(p.To-p.From)+1)
	for i := int(p.From); i <= int(p.To); i++ {
		out = append(out, uint16(i))
	}
	return out
}

func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	lo, hi, split := strings.Cut(s, "-")
	from, err := parsePort(lo)
	if err != nil {
		return PortRange{}, err
	}
	if !split {
		return PortRange{From: from, To: from}, nil
	}
	to, err := parsePort(hi)
	if err != nil {
		return PortRange{}, err
	}
	if to < from {
		return PortRange{}, fmt.Errorf("port range %q ist verkehrt herum", s)
	}
	return PortRange{From: from, To: to}, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("ungueltiger Port %q", strings.TrimSpace(s))
	}
	return uint16(n), nil
}

// ParsePortList reads a comma separated list such as "47984, 47989, 47998-48000".
func ParsePortList(s string) ([]PortRange, error) {
	var out []PortRange
	for _, field := range strings.Split(s, ",") {
		if strings.TrimSpace(field) == "" {
			continue
		}
		pr, err := ParsePortRange(field)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("leere Portliste")
	}
	return out, nil
}

func FormatPortList(ranges []PortRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, ", ")
}

// NftElements renders the list for an nftables set: "47984, 47998-48000".
func NftElements(ranges []PortRange) string {
	return FormatPortList(ranges)
}

// MultiportSpec renders the list for iptables -m multiport: "47984,47998:48000".
func MultiportSpec(ranges []PortRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		if r.From == r.To {
			parts = append(parts, strconv.Itoa(int(r.From)))
		} else {
			parts = append(parts, fmt.Sprintf("%d:%d", r.From, r.To))
		}
	}
	return strings.Join(parts, ",")
}

// ExpandPorts flattens ranges into single ports, used where no range syntax exists
// (conntrack -D takes one port at a time).
func ExpandPorts(ranges []PortRange) []uint16 {
	var out []uint16
	for _, r := range ranges {
		out = append(out, r.Ports()...)
	}
	return out
}

func (p PortRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *PortRange) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// tolerate a bare number
		var n int
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		s = strconv.Itoa(n)
	}
	pr, err := ParsePortRange(s)
	if err != nil {
		return err
	}
	*p = pr
	return nil
}
