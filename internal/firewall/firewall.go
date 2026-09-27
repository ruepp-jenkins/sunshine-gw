// Package firewall renders and loads the kernel ruleset that does the actual
// forwarding. Nothing in this process ever touches a packet: it writes nftables
// rules and lets netfilter forward in the kernel, which is what keeps the added
// latency down to a conntrack lookup instead of a userspace round trip.
package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
	"github.com/ruepp-jenkins/sunshine-gw/internal/events"
)

const (
	// TableName holds the NAT and forward rules; it exists only while forwarding is on.
	TableName = "sunshine_gw"
	// GuardTableName drops the forwarded ports on the gateway itself. It stays loaded
	// at all times so a disabled gateway is a blackhole rather than a closed port.
	GuardTableName = "sunshine_gw_guard"
)

type Manager struct {
	log     *events.Log
	timeout time.Duration
}

func New(log *events.Log) *Manager {
	return &Manager{log: log, timeout: 10 * time.Second}
}

type cmdResult struct {
	out string
	err error
}

func (m *Manager) run(name string, stdin string, args ...string) cmdResult {
	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		err = fmt.Errorf("%s %s: %w%s", name, strings.Join(args, " "), err, detail(out))
	}
	return cmdResult{out: out, err: err}
}

func detail(out string) string {
	if out == "" {
		return ""
	}
	return ": " + out
}

func has(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// Apply loads the forwarding ruleset and opens the forward path through Docker's
// FORWARD policy. The whole nft ruleset is replaced in one transaction.
func (m *Manager) Apply(st config.State) error {
	if err := m.ApplyGuard(st); err != nil {
		return err
	}
	ruleset, err := RenderForward(st)
	if err != nil {
		return err
	}
	// Permission first, translation second: the other order would leave a short window
	// in which packets are already redirected but not yet allowed through.
	if err := m.ensureForwardAccept(st); err != nil {
		// Not fatal: without it packets may be dropped by Docker's FORWARD policy,
		// which the health check reports. Better to run degraded and say so.
		m.log.Warnf("Forward-Freigabe konnte nicht gesetzt werden: %v", err)
	}
	res := m.run("nft", ruleset, "-f", "-")
	return res.err
}

// ApplyGuard loads the blackhole table. Idempotent, safe to call on every change.
func (m *Manager) ApplyGuard(st config.State) error {
	ruleset, err := RenderGuard(st)
	if err != nil {
		return err
	}
	res := m.run("nft", ruleset, "-f", "-")
	return res.err
}

// Clear removes the forwarding ruleset, drops the forward permission and kills the
// conntrack entries of flows that are still running. Without the conntrack flush the
// kill switch would not be one: established streams keep being translated.
func (m *Manager) Clear(st config.State) error {
	// Nothing was translated, so there is nothing to tear down either. Saves a handful
	// of subprocesses on every settings change while the gateway is off.
	wasLoaded := m.TableLoaded()
	ruleset := RenderDelete(TableName)
	if res := m.run("nft", ruleset, "-f", "-"); res.err != nil {
		return res.err
	}
	if err := m.clearForwardAccept(); err != nil {
		m.log.Warnf("Forward-Freigabe konnte nicht entfernt werden: %v", err)
	}
	if !wasLoaded {
		return nil
	}
	if n, err := m.FlushConntrack(st); err != nil {
		m.log.Warnf("conntrack-Flush unvollstaendig: %v", err)
	} else if n > 0 {
		m.log.Infof("%d laufende Verbindung(en) beendet", n)
	}
	return nil
}

// TableLoaded reports whether the forwarding table is currently in the kernel.
func (m *Manager) TableLoaded() bool {
	res := m.run("nft", "", "list", "table", "inet", TableName)
	return res.err == nil
}
