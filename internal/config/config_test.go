package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePortList(t *testing.T) {
	ranges, err := ParsePortList(" 47984, 47998-48000 ,48002")
	if err != nil {
		t.Fatalf("unerwarteter Fehler: %v", err)
	}
	if got, want := FormatPortList(ranges), "47984, 47998-48000, 48002"; got != want {
		t.Errorf("FormatPortList = %q, want %q", got, want)
	}
	if got, want := MultiportSpec(ranges), "47984,47998:48000,48002"; got != want {
		t.Errorf("MultiportSpec = %q, want %q", got, want)
	}
	if got, want := len(ExpandPorts(ranges)), 5; got != want {
		t.Errorf("ExpandPorts = %d Ports, want %d", got, want)
	}
}

func TestParsePortListRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "0", "65536", "48000-47998", "abc", "47989-"} {
		if _, err := ParsePortList(in); err == nil {
			t.Errorf("ParsePortList(%q) haette fehlschlagen muessen", in)
		}
	}
}

func TestNextOffTimeCrossesMidnight(t *testing.T) {
	st := Defaults()
	st.DailyOffTime = "03:00"
	loc := st.Location()
	now := time.Date(2026, 9, 27, 22, 30, 0, 0, loc)

	next := st.NextOffTime(now)
	want := time.Date(2026, 9, 28, 3, 0, 0, 0, loc)
	if !next.Equal(want) {
		t.Errorf("NextOffTime = %s, want %s", next, want)
	}
	prev := st.PrevOffTime(now)
	if wantPrev := time.Date(2026, 9, 27, 3, 0, 0, 0, loc); !prev.Equal(wantPrev) {
		t.Errorf("PrevOffTime = %s, want %s", prev, wantPrev)
	}
}

// The off time must land on the wall clock, not 24 h after the previous one, or it
// would drift by an hour twice a year.
func TestNextOffTimeAcrossDSTChange(t *testing.T) {
	st := Defaults()
	st.DailyOffTime = "03:00"
	loc := st.Location()
	// Night of 25.10.2026: Europe/Berlin falls back from CEST to CET, so the wall
	// clock distance between two 03:00 shutdowns across that night is 25 hours.
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, loc)
	next := st.NextOffTime(now)
	if next.Hour() != 3 {
		t.Errorf("NextOffTime = %s, erwartet 03:00 Ortszeit", next)
	}
	after := st.NextOffTime(next.Add(time.Minute))
	if after.Hour() != 3 {
		t.Errorf("uebernaechste Abschaltung = %s, erwartet 03:00 Ortszeit", after)
	}
	if d := after.Sub(next); d != 25*time.Hour {
		t.Errorf("Abstand ueber die Zeitumstellung = %v, erwartet 25h", d)
	}
}

func TestMissedOffCatchUp(t *testing.T) {
	st := Defaults()
	st.DailyOffTime = "03:00"
	loc := st.Location()
	st.Enabled = true
	st.EnabledAt = time.Date(2026, 9, 27, 21, 0, 0, 0, loc)

	// Restart the next morning: the 03:00 shutdown fell due in between.
	if !st.MissedOff(time.Date(2026, 9, 28, 8, 0, 0, 0, loc)) {
		t.Error("MissedOff = false, erwartet true (Abschaltung wurde verschlafen)")
	}
	// Restart before the off time: nothing was missed.
	if st.MissedOff(time.Date(2026, 9, 27, 23, 0, 0, 0, loc)) {
		t.Error("MissedOff = true, erwartet false")
	}
	st.Enabled = false
	if st.MissedOff(time.Date(2026, 9, 28, 8, 0, 0, 0, loc)) {
		t.Error("MissedOff bei ausgeschalteter Weiterleitung muss false sein")
	}
}

func TestValidate(t *testing.T) {
	base := func() State {
		st := Defaults()
		st.Target = "10.10.10.5"
		st.GatewayIP = "10.10.10.20"
		st.LANCIDR = "10.10.10.0/24"
		return st
	}
	valid := base()
	if err := valid.Validate(); err != nil {
		t.Fatalf("gueltiger Zustand abgelehnt: %v", err)
	}
	st := base()
	st.Target = "kein-ip"
	if err := st.Validate(); err == nil {
		t.Error("ungueltige Zieladresse wurde akzeptiert")
	}
	st = base()
	st.Target = ""
	st.Enabled = true
	if err := st.Validate(); err == nil {
		t.Error("Aktivierung ohne Ziel wurde akzeptiert")
	}
	st = base()
	st.DailyOffTime = "25:00"
	if err := st.Validate(); err == nil {
		t.Error("ungueltige Uhrzeit wurde akzeptiert")
	}
	st = base()
	st.LANCIDR = ""
	if err := st.Validate(); err == nil {
		t.Error("\"nur externe Quellen\" ohne LAN-Netz wurde akzeptiert")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	st := Defaults()
	st.Target = "10.10.10.5"
	st.GatewayIP = "10.10.10.20"
	st.LANCIDR = "10.10.10.0/24"
	st.Iface = "eth0"
	st.Enabled = true
	st.EnabledAt = time.Now().Truncate(time.Second)

	if err := Save(path, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Target != st.Target || got.Enabled != st.Enabled || !got.EnabledAt.Equal(st.EnabledAt) {
		t.Errorf("Round-Trip verloren: %+v", got)
	}
	if FormatPortList(got.UDPPorts) != FormatPortList(st.UDPPorts) {
		t.Errorf("UDP-Ports = %q, want %q", FormatPortList(got.UDPPorts), FormatPortList(st.UDPPorts))
	}
	// No leftover temporary files from the atomic write.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d Dateien im Verzeichnis, erwartet 1: %v", len(entries), entries)
	}
}

func TestLoadMissingFileYieldsDefaults(t *testing.T) {
	st, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("fehlende Datei muss die Defaults liefern, nicht scheitern: %v", err)
	}
	if st.Enabled {
		t.Error("frischer Zustand muss ausgeschaltet sein")
	}
	if FormatPortList(st.TCPPorts) != "47984, 47989, 48010" {
		t.Errorf("TCP-Defaults = %q", FormatPortList(st.TCPPorts))
	}
	if FormatPortList(st.UDPPorts) != "47998-48000, 48002" {
		t.Errorf("UDP-Defaults = %q", FormatPortList(st.UDPPorts))
	}
}

func TestSkipIface(t *testing.T) {
	for _, name := range []string{"docker0", "br-1a2b", "veth9f2", "virbr0", "lo", "wg0"} {
		if !skipIface(name) {
			t.Errorf("skipIface(%q) = false, erwartet true", name)
		}
	}
	for _, name := range []string{"eth0", "enp3s0", "ens18", "wlan0"} {
		if skipIface(name) {
			t.Errorf("skipIface(%q) = true, erwartet false", name)
		}
	}
}
