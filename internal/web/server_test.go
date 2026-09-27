package web

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/config"
	"github.com/ruepp-jenkins/sunshine-gw/internal/control"
	"github.com/ruepp-jenkins/sunshine-gw/internal/events"
	"github.com/ruepp-jenkins/sunshine-gw/internal/firewall"
)

// stubFirewall keeps the web tests away from the kernel.
type stubFirewall struct{ loaded bool }

func (s *stubFirewall) Apply(config.State) error      { s.loaded = true; return nil }
func (s *stubFirewall) ApplyGuard(config.State) error { return nil }
func (s *stubFirewall) Clear(config.State) error      { s.loaded = false; return nil }
func (s *stubFirewall) TableLoaded() bool             { return s.loaded }
func (s *stubFirewall) AllCounters() []firewall.Counter {
	return []firewall.Counter{{Label: "dnat-udp", Chain: "prerouting", Packets: 1234567, Bytes: 987654321}}
}
func (s *stubFirewall) Health(config.State) []firewall.Check {
	return []firewall.Check{{Name: "ip_forward", Level: firewall.OK, Message: "net.ipv4.ip_forward=1"}}
}
func (s *stubFirewall) ActiveFlows(config.State) int { return 3 }

const (
	testUser = "admin"
	testPass = "streng-geheim-123"
)

func newTestServer(t *testing.T) (*Server, http.Handler, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	st := config.Defaults()
	st.Target = "10.10.10.5"
	st.GatewayIP = "10.10.10.20"
	st.LANCIDR = "10.10.10.0/24"
	st.Iface = "eth0"
	if err := config.Save(path, st); err != nil {
		t.Fatal(err)
	}
	evlog := events.New(log.New(os.Stderr, "", 0))
	ctrl, err := control.New(path, &stubFirewall{}, evlog)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword(testPass)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ctrl, evlog, testUser, hash)
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), path
}

func authed(t *testing.T, method, target string, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	r.SetBasicAuth(testUser, testPass)
	return r
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("streng-geheim-123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "pbkdf2-sha256.") {
		t.Errorf("unerwartetes Hash-Format: %q", hash)
	}
	// The hash goes into a .env file that Docker Compose also reads for interpolation.
	// A "$" in there is taken as a variable reference and replaced by a blank string, so
	// the container would receive a truncated hash and every login would fail silently.
	// Same for characters that would need quoting in YAML or a shell.
	if !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(hash) {
		t.Errorf("Hash enthaelt Zeichen, die in .env, YAML oder Shell interpretiert werden: %q", hash)
	}
	if !VerifyPassword(hash, "streng-geheim-123") {
		t.Error("korrektes Passwort wurde abgelehnt")
	}
	if VerifyPassword(hash, "streng-geheim-124") {
		t.Error("falsches Passwort wurde akzeptiert")
	}
	if VerifyPassword("kaputt", "streng-geheim-123") {
		t.Error("kaputter Hash wurde akzeptiert")
	}
	second, err := HashPassword("streng-geheim-123")
	if err != nil {
		t.Fatal(err)
	}
	if second == hash {
		t.Error("gleicher Hash fuer zwei Aufrufe - Salt fehlt")
	}
	if _, err := HashPassword("kurz"); err == nil {
		t.Error("zu kurzes Passwort wurde akzeptiert")
	}
}

// The gateway must refuse to start on an unusable hash instead of answering every login
// with 401. The message for a "$" in the value names the actual cause, because that is
// what Compose's interpolation leaves behind.
func TestValidateHash(t *testing.T) {
	good, err := HashPassword("streng-geheim-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHash(good); err != nil {
		t.Errorf("gueltiger Hash abgelehnt: %v", err)
	}
	for _, bad := range []string{"", "   ", "kaputt", "pbkdf2-sha256.1.AAAA.AAAA", "pbkdf2-sha256.210000.AAAA"} {
		if err := ValidateHash(bad); err == nil {
			t.Errorf("ValidateHash(%q) = nil, erwartet ein Fehler", bad)
		}
	}
	// A hash mangled by Compose, i.e. the old PHC-style format.
	err = ValidateHash("pbkdf2-sha256$210000$21Mcdc8CGua/IqLkg/5VOw$")
	if err == nil {
		t.Fatal("Hash im alten $-Format wurde akzeptiert")
	}
	if !strings.Contains(err.Error(), "Compose") {
		t.Errorf("Meldung nennt die Ursache nicht: %v", err)
	}
}

func TestUnauthenticatedIsRejected(t *testing.T) {
	_, h, _ := newTestServer(t)
	for _, target := range []string{"/", "/api/status", "/config", "/toggle"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s ohne Anmeldung = %d, erwartet 401", target, w.Code)
		}
	}
}

func TestIndexRenders(t *testing.T) {
	_, h, _ := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodGet, "/", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("Status = %d, Body: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"Sunshine Gateway",
		"Weiterleitung einschalten",
		"10.10.10.5",
		"47998-48000, 48002",
		"dnat-udp",
		"1.234.567", // counter formatting
		"941.9 MB",  // byte formatting
		"/static/app.js",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Seite enthaelt %q nicht", want)
		}
	}
}

func TestStaticAssetsAreServed(t *testing.T) {
	_, h, _ := newTestServer(t)
	for _, target := range []string{"/static/app.css", "/static/app.js"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s = %d, erwartet 200", target, w.Code)
		}
	}
}

func TestAPIStatusIsJSON(t *testing.T) {
	_, h, _ := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodGet, "/api/status", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("Status = %d", w.Code)
	}
	var status control.Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("kein gueltiges JSON: %v", err)
	}
	if status.Target != "10.10.10.5" || len(status.Counters) != 1 || len(status.Checks) != 1 {
		t.Errorf("Status = %+v", status)
	}
	// Flows are only counted while forwarding is on; off means off.
	if status.Enabled || status.ActiveFlows != 0 {
		t.Errorf("ausgeschaltet erwartet, ActiveFlows = %d", status.ActiveFlows)
	}
}

func csrfToken(t *testing.T, h http.Handler) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodGet, "/", ""))
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("kein CSRF-Token in der Seite")
	}
	return m[1]
}

func TestPostWithoutCSRFIsRejected(t *testing.T) {
	_, h, _ := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodPost, "/toggle", "enable=1"))
	if w.Code != http.StatusForbidden {
		t.Errorf("POST ohne Token = %d, erwartet 403", w.Code)
	}
}

func TestGetOnPostEndpointIsRejected(t *testing.T) {
	_, h, _ := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodGet, "/toggle", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET auf /toggle = %d, erwartet 405", w.Code)
	}
}

func TestToggleAndConfigRoundTrip(t *testing.T) {
	_, h, path := newTestServer(t)
	token := csrfToken(t, h)

	form := url.Values{"csrf": {token}, "enable": {"1"}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodPost, "/toggle", form.Encode()))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("Toggle = %d, Body: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "msg=") {
		t.Errorf("Redirect ohne Meldung: %q", loc)
	}
	stored, _ := config.Load(path)
	if !stored.Enabled {
		t.Error("Weiterleitung wurde nicht eingeschaltet")
	}

	cfg := url.Values{
		"csrf":         {token},
		"target":       {"10.10.10.9"},
		"dailyOffTime": {"02:15"},
		"timezone":     {"Europe/Berlin"},
		"tcpPorts":     {"47984, 47989, 48010"},
		"udpPorts":     {"47998-48000, 48002"},
		"externalOnly": {"1"},
		"gatewayIP":    {"10.10.10.20"},
		"lanCIDR":      {"10.10.10.0/24"},
		"iface":        {"eth0"},
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodPost, "/config", cfg.Encode()))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("Config = %d, Body: %s", w.Code, w.Body.String())
	}
	stored, _ = config.Load(path)
	if stored.Target != "10.10.10.9" || stored.DailyOffTime != "02:15" {
		t.Errorf("Einstellungen nicht uebernommen: %+v", stored)
	}
	if !stored.Enabled {
		t.Error("das Speichern von Einstellungen darf die Weiterleitung nicht abschalten")
	}
}

func TestConfigErrorIsReportedToUser(t *testing.T) {
	_, h, _ := newTestServer(t)
	token := csrfToken(t, h)
	cfg := url.Values{
		"csrf":     {token},
		"target":   {"keine-ip"},
		"tcpPorts": {"47984"},
		"udpPorts": {"47998"},
		"timezone": {"Europe/Berlin"},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodPost, "/config", cfg.Encode()))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("Status = %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("Fehler wurde nicht an die Seite zurueckgegeben: %q", loc)
	}
}

func TestBruteForceIsBlocked(t *testing.T) {
	_, h, _ := newTestServer(t)
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth(testUser, "falsch")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodGet, "/", ""))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("nach fuenf Fehlversuchen = %d, erwartet 429", w.Code)
	}
}

// The page carries the sections; their content is drawn in the browser from /api/status,
// so the JSON is what has to contain the data.
func TestStatusCarriesMetrics(t *testing.T) {
	srv, h, _ := newTestServer(t)
	store := srv.ctrl.Metrics()
	t0 := time.Now()
	counters := func(up, down uint64) []firewall.Counter {
		return []firewall.Counter{
			{Label: firewall.LabelFwdUDP, Bytes: up},
			{Label: firewall.LabelFwdReply, Bytes: down},
		}
	}
	flows := []firewall.Flow{{
		Proto: "udp", ClientIP: "203.0.113.9", ClientPort: 51234, Port: 47998,
		BytesUp: 1_000, BytesDown: 8_000, Accounted: true,
	}}
	store.Observe(counters(0, 0), nil, true, t0)
	store.Observe(counters(500_000, 4_000_000), flows, true, t0.Add(5*time.Second))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodGet, "/api/status", ""))
	var status control.Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatalf("kein gueltiges JSON: %v", err)
	}
	if len(status.Metrics.Samples) != 1 {
		t.Fatalf("%d Samples im Status", len(status.Metrics.Samples))
	}
	if got := status.Metrics.Samples[0].Down; got != 800_000 {
		t.Errorf("Download-Rate = %d B/s, erwartet 800000", got)
	}
	if len(status.Metrics.Clients) != 1 || status.Metrics.Clients[0].IP != "203.0.113.9" {
		t.Errorf("Clients = %+v", status.Metrics.Clients)
	}
	if !status.Metrics.Accounted {
		t.Error("Accounting-Flag fehlt im Status")
	}

	page := httptest.NewRecorder()
	h.ServeHTTP(page, authed(t, http.MethodGet, "/", ""))
	for _, want := range []string{"Durchsatz", "id=\"chart\"", "Clients", "id=\"clients\"", "/forget"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("Seite enthaelt %q nicht", want)
		}
	}
}

// The record says who reached the gateway and how much they moved, so deleting it has to
// work - and must not be doable without the CSRF token.
func TestForgetClearsClientHistory(t *testing.T) {
	srv, h, _ := newTestServer(t)
	store := srv.ctrl.Metrics()
	t0 := time.Now()
	store.Observe(nil, nil, true, t0)
	store.Observe(nil, []firewall.Flow{{
		Proto: "udp", ClientIP: "203.0.113.9", ClientPort: 1, Port: 47998, Accounted: true,
	}}, true, t0.Add(5*time.Second))
	if len(store.Snapshot().Clients) != 1 {
		t.Fatal("Voraussetzung: ein Client im Verlauf")
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodPost, "/forget", "csrf=falsch"))
	if w.Code != http.StatusForbidden {
		t.Errorf("Loeschen ohne Token = %d, erwartet 403", w.Code)
	}
	if len(store.Snapshot().Clients) != 1 {
		t.Error("Verlauf wurde ohne gueltiges Token geloescht")
	}

	token := csrfToken(t, h)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, authed(t, http.MethodPost, "/forget", url.Values{"csrf": {token}}.Encode()))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("Loeschen = %d, Body: %s", w.Code, w.Body.String())
	}
	if got := len(store.Snapshot().Clients); got != 0 {
		t.Errorf("%d Clients nach dem Loeschen", got)
	}
}
