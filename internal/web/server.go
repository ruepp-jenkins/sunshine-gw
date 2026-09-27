// Package web serves the single-page control UI.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/ruepp-jenkins/sunshine-gw/internal/control"
	"github.com/ruepp-jenkins/sunshine-gw/internal/events"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	ctrl *control.Controller
	log  *events.Log

	user         string
	passwordHash string
	// Version is the build the binary was made from, shown in the page footer.
	Version string

	tmpl     *template.Template
	csrf     string
	throttle *throttle
}

func NewServer(ctrl *control.Controller, log *events.Log, user, passwordHash string) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"checked": func(b bool) template.HTMLAttr {
			if b {
				return template.HTMLAttr("checked")
			}
			return ""
		},
		"bytes": humanBytes,
		"num":   humanNum,
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	return &Server{
		ctrl:         ctrl,
		log:          log,
		user:         user,
		passwordHash: passwordHash,
		tmpl:         tmpl,
		csrf:         base64.RawURLEncoding.EncodeToString(token),
		throttle:     newThrottle(),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	mux.HandleFunc("/toggle", s.requireAuth(s.handleToggle))
	mux.HandleFunc("/config", s.requireAuth(s.handleConfig))
	mux.HandleFunc("/forget", s.requireAuth(s.handleForget))
	mux.HandleFunc("/api/status", s.requireAuth(s.handleAPIStatus))
	mux.Handle("/static/", http.FileServer(http.FS(assets)))
	return noStore(mux)
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type pageData struct {
	Status  control.Status
	CSRF    string
	Message string
	Error   string
	Version string
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := pageData{
		Status:  s.ctrl.Status(),
		CSRF:    s.csrf,
		Message: r.URL.Query().Get("msg"),
		Error:   r.URL.Query().Get("err"),
		Version: s.Version,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		s.log.Errorf("Seite konnte nicht gerendert werden: %v", err)
	}
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.ctrl.Status()); err != nil {
		s.log.Errorf("Status-JSON: %v", err)
	}
}

func (s *Server) handleToggle(w http.ResponseWriter, r *http.Request) {
	if !s.checkPost(w, r) {
		return
	}
	on := r.FormValue("enable") == "1"
	who := fmt.Sprintf("manuell von %s", remoteAddr(r))
	if err := s.ctrl.SetEnabled(on, who); err != nil {
		s.redirect(w, r, "", err.Error())
		return
	}
	if on {
		s.redirect(w, r, "Weiterleitung ist aktiv.", "")
	} else {
		s.redirect(w, r, "Weiterleitung ist aus, laufende Verbindungen wurden beendet.", "")
	}
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !s.checkPost(w, r) {
		return
	}
	u := control.Update{
		Target:       r.FormValue("target"),
		DailyOffTime: r.FormValue("dailyOffTime"),
		Timezone:     r.FormValue("timezone"),
		TCPPorts:     r.FormValue("tcpPorts"),
		UDPPorts:     r.FormValue("udpPorts"),
		ExternalOnly: r.FormValue("externalOnly") == "1",
		Flowtable:    r.FormValue("flowtable") == "1",
		GatewayIP:    r.FormValue("gatewayIP"),
		LANCIDR:      r.FormValue("lanCIDR"),
		Iface:        r.FormValue("iface"),
	}
	if err := s.ctrl.Update(u); err != nil {
		s.redirect(w, r, "", err.Error())
		return
	}
	s.redirect(w, r, "Einstellungen gespeichert.", "")
}

// handleForget drops the recorded clients. The record says who reached the gateway and how
// much they moved, so there has to be an obvious way to get rid of it.
func (s *Server) handleForget(w http.ResponseWriter, r *http.Request) {
	if !s.checkPost(w, r) {
		return
	}
	s.ctrl.Metrics().Forget()
	s.log.Infof("Client-Verlauf geloescht (von %s)", remoteAddr(r))
	s.redirect(w, r, "Verlauf geloescht.", "")
}

// checkPost enforces the method and the CSRF token. The token lives for the lifetime
// of the process and only ever appears in the authenticated page.
func (s *Server) checkPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "nur POST", http.StatusMethodNotAllowed)
		return false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Formular unlesbar", http.StatusBadRequest)
		return false
	}
	if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(s.csrf)) != 1 {
		http.Error(w, "CSRF-Token ungueltig - Seite neu laden", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	q := url.Values{}
	if msg != "" {
		q.Set("msg", msg)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	target := "/"
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// HTTPServer builds the server; the caller owns its lifetime so it can shut down
// gracefully on SIGTERM.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
