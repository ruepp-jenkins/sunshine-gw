package firewall

import (
	"encoding/json"
	"fmt"
)

// Counter is one labelled rule counter, read back from the kernel. The UI shows these
// so it is immediately visible whether packets actually arrive.
type Counter struct {
	Label   string `json:"label"`
	Chain   string `json:"chain"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type nftDump struct {
	Nftables []struct {
		Rule *struct {
			Chain   string                       `json:"chain"`
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		} `json:"rule"`
	} `json:"nftables"`
}

type nftCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Counters reads the counters of one table. A missing table is not an error - that is
// simply the disabled state.
func (m *Manager) Counters(table string) ([]Counter, error) {
	res := m.run("nft", "", "-j", "list", "table", "inet", table)
	if res.err != nil {
		return nil, nil
	}
	var dump nftDump
	if err := json.Unmarshal([]byte(res.out), &dump); err != nil {
		return nil, fmt.Errorf("nft-JSON nicht lesbar: %w", err)
	}
	var out []Counter
	for _, item := range dump.Nftables {
		if item.Rule == nil || item.Rule.Comment == "" {
			continue
		}
		for _, expr := range item.Rule.Expr {
			raw, ok := expr["counter"]
			if !ok {
				continue
			}
			var c nftCounter
			if err := json.Unmarshal(raw, &c); err != nil {
				continue
			}
			out = append(out, Counter{
				Label:   item.Rule.Comment,
				Chain:   item.Rule.Chain,
				Packets: c.Packets,
				Bytes:   c.Bytes,
			})
			break
		}
	}
	return out, nil
}

// AllCounters returns the forwarding counters followed by the blackhole counters.
func (m *Manager) AllCounters() []Counter {
	var out []Counter
	if c, err := m.Counters(TableName); err == nil {
		out = append(out, c...)
	}
	if c, err := m.Counters(GuardTableName); err == nil {
		out = append(out, c...)
	}
	return out
}
