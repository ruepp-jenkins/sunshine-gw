// Command gateway is the control plane for a Sunshine port forwarding gateway: it
// renders an nftables ruleset, loads it, and offers a small web UI to switch the
// forwarding on and off, point it somewhere else, and have it shut itself off at a
// fixed time every day. Packets are forwarded by the kernel, never by this process.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	// The daily off time is computed in a named location, so the zone database is
	// compiled into the binary instead of relying on the image having tzdata.
	_ "time/tzdata"

	"github.com/stefan/sunshine-gateway/internal/config"
	"github.com/stefan/sunshine-gateway/internal/control"
	"github.com/stefan/sunshine-gateway/internal/events"
	"github.com/stefan/sunshine-gateway/internal/firewall"
	"github.com/stefan/sunshine-gateway/internal/scheduler"
	"github.com/stefan/sunshine-gateway/internal/web"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "hash-password":
			run(hashPassword(os.Args[2:]))
			return
		case "print-ruleset":
			run(printRuleset(os.Args[2:]))
			return
		}
	}

	var (
		listen      = flag.String("listen", envOr("GW_LISTEN", "127.0.0.1:8080"), "Adresse des Web-Interfaces (host:port)")
		statePath   = flag.String("state", envOr("GW_STATE", "/data/config.json"), "Pfad der Zustandsdatei")
		clearOnExit = flag.Bool("clear-on-exit", true,
			"beim Beenden die Weiterleitung entfernen (der gespeicherte Zustand bleibt, ein Neustart stellt sie wieder her)")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	evlog := events.New(logger)

	user := envOr("GW_USER", "admin")
	hash := os.Getenv("GW_PASSWORD_HASH")
	if strings.TrimSpace(hash) == "" {
		logger.Fatalf("GW_PASSWORD_HASH ist nicht gesetzt. Hash erzeugen mit:\n" +
			"  docker compose run --rm sunshine-gateway hash-password")
	}

	fw := firewall.New(evlog)
	ctrl, err := control.New(*statePath, fw, evlog)
	if err != nil {
		logger.Fatalf("Zustand konnte nicht geladen werden: %v", err)
	}
	if err := ctrl.Start(); err != nil {
		evlog.Errorf("Start unvollstaendig: %v", err)
	}
	for _, c := range fw.Health(ctrl.State()) {
		if c.Level != firewall.OK {
			evlog.Warnf("%s: %s", c.Name, c.Message)
		}
	}

	srv, err := web.NewServer(ctrl, evlog, user, hash)
	if err != nil {
		logger.Fatalf("Web-Interface: %v", err)
	}
	httpSrv := srv.HTTPServer(*listen)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sched := scheduler.New(ctrl, evlog)
	go sched.Run(ctx)

	go func() {
		if strings.HasPrefix(*listen, "0.0.0.0:") || strings.HasPrefix(*listen, ":") {
			evlog.Warnf("Web-Interface lauscht auf allen Adressen (%s) - besser an die LAN-Adresse binden", *listen)
		}
		evlog.Infof("Web-Interface auf http://%s", *listen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("HTTP-Server beendet: %v", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Printf("Signal empfangen, beende")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("HTTP-Shutdown: %v", err)
	}

	// Without a running control plane there is nobody left to honour the daily off
	// time, so the forwarding does not outlive the process. The stored state keeps
	// Enabled as it was; a restart brings it straight back.
	if *clearOnExit {
		if err := fw.Clear(ctrl.State()); err != nil {
			logger.Printf("Aufraeumen: %v", err)
		} else {
			logger.Printf("Weiterleitung entfernt")
		}
	}
}

func run(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}

// printRuleset renders what would be loaded into the kernel, for debugging and for
// checking the syntax with `nft -c -f -` without touching the running state.
func printRuleset(args []string) error {
	fs := flag.NewFlagSet("print-ruleset", flag.ExitOnError)
	statePath := fs.String("state", envOr("GW_STATE", "/data/config.json"), "Pfad der Zustandsdatei")
	target := fs.String("target", "", "Zieladresse ueberschreiben")
	gateway := fs.String("gateway", "", "eigene Adresse ueberschreiben")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := config.Load(*statePath)
	if err != nil {
		return err
	}
	if *target != "" {
		st.Target = *target
	}
	if *gateway != "" {
		st.GatewayIP = *gateway
	}
	guard, err := firewall.RenderGuard(st)
	if err != nil {
		return err
	}
	fmt.Print(guard)
	forward, err := firewall.RenderForward(st)
	if err != nil {
		return err
	}
	fmt.Print(forward)
	return nil
}

func hashPassword(args []string) error {
	var password string
	switch {
	case len(args) > 0:
		password = args[0]
	default:
		fmt.Fprintln(os.Stderr, "Passwort eingeben (wird sichtbar) und mit Enter abschliessen:")
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return err
		}
		password = strings.TrimRight(string(b), "\r\n")
	}
	hash, err := web.HashPassword(password)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	fmt.Fprintln(os.Stderr, "\nIn die .env-Datei uebernehmen:")
	fmt.Fprintf(os.Stderr, "GW_PASSWORD_HASH=%s\n", hash)
	return nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
