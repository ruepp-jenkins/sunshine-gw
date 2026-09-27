# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Was das ist

Ein schaltbares Weiterleitungs-Gateway zwischen FRITZ!Box und Sunshine-Server: die Box hat
eine permanente Portfreigabe auf dieses Gateway, das Gateway entscheidet per Web-Interface,
ob und wohin weitergeleitet wird (plus taegliche Zwangsabschaltung). Hintergrund steht im
README; der Anlass war, dass FRITZ!OS 8.25 `AddPortMapping` ueber TR-064 verweigert und UPnP
bewusst aus bleiben soll.

## Der zentrale Grundsatz

**Dieser Prozess leitet keine Pakete weiter.** Er rendert ein nftables-Regelwerk und laedt
es; weitergeleitet wird im Kernel per DNAT. Alles, was Pakete durch den Userspace zwingen
wuerde (Proxy, Mirror, pcap), ist ausgeschlossen — Game-Streaming reagiert auf Jitter. Wer
ein Feature baut, das Pakete anfassen muesste, baut das falsche Feature.

Daraus folgt auch: Messwerte kommen aus Zustand, den der Kernel ohnehin fuehrt
(Regel-Zaehler, conntrack), abgefragt von einem Sampler alle 5 s — nie aus dem Datenpfad.

## Kommandos

Es gibt **kein lokales Go**; alles laeuft in Containern (die `GO`-Variable im Makefile).
Das Test-Image ist `golang:1` (Debian), nicht die Alpine-Variante — `-race` braucht gcc.

```sh
make test          # go test -race -count=1 ./...  (wie in der CI)
make vet
make build         # statisches Binary ./gateway
make check-chart   # Zeichenlogik von app.js gegen eine DOM-Attrappe (node-Container)
make image         # Image lokal bauen; Testsuite laeuft IM Build
make pull / up / down / logs / restart
make selftest      # auf dem Gateway: Ruleset gegen den echten Kernel, Host-Voraussetzungen
make ruleset       # gerendertes nftables-Ruleset des laufenden Containers
make hash          # Passwort-Hash erzeugen
```

Einzelner Test:

```sh
docker run --rm -v "$PWD":/src -w /src --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache golang:1 \
  go test -race -count=1 -run TestStrayDropComesAfterReplyAccept ./internal/firewall/
```

Regelwerk ohne laufenden Container ansehen (gibt beide Blackhole-Varianten aus):

```sh
./gateway print-ruleset -state /pfad/config.json -target 10.0.0.5 -gateway 10.0.0.1
```

## Aufbau

`cmd/gateway` verdrahtet und hat die Subcommands `hash-password` und `print-ruleset`.
`cmd/junitreport` wandelt `go test -json` in JUnit-XML (nur fuer die CI).

- `internal/config` — Zustand (`/data/config.json`), atomar geschrieben, Portlisten,
  Zeitplan-Arithmetik ueber `time.Date` in der Location (nicht +24 h, wegen DST).
- `internal/firewall` — rendert und laedt das Regelwerk, Health-Checks, conntrack.
- `internal/control` — haelt Zustand und Kernel in Deckung; besitzt den Metrik-Store.
- `internal/scheduler` — taegliche Abschaltung, mit Nachholen beim Start.
- `internal/metrics` — Sampler und Verlauf (`/data/metrics.json`).
- `internal/web` — eine Seite, Basic Auth, CSRF, `/api/status`.

Zwei nftables-Tabellen: `inet sunshine_gw` (nat + forward, existiert nur im Ein-Zustand)
und `inet sunshine_gw_guard` (immer geladen, verwirft die freigegebenen Ports am Gateway).

## Dinge, die bei Aenderungen kaputtgehen

**Die Blackhole-Tabelle hat zwei Formen.** Im Aus-Zustand bekommt sie eine Kette im
`raw`-Hook (-300), die vor conntrack (-200) verwirft; sonst legt jedes Paket aus dem
Internet erst einen conntrack-Eintrag an. Im Ein-Zustand darf diese Kette nicht existieren,
weil `raw` vor `dstnat` laeuft und die zu uebersetzenden Pakete wegwerfen wuerde. Deshalb
baut `Apply` den Guard **vor** der DNAT-Tabelle neu und `Clear` **vor** dem Loeschen.

**Regelreihenfolge in der forward-Kette ist tragend.** Die `fwd-stray-*`-Drops muessen
hinter den accept-Regeln stehen: der Ephemeral-Port-Bereich enthaelt 47984–48010, ein Client
darf 47998 als Quellport waehlen, und die Antwort an ihn traegt dann `dport=47998`. Vorn
platziert verwirft die Regel genau diese Antwort — sporadisch und schwer zu finden.
`TestStrayDropComesAfterReplyAccept` sichert das ab.

**Abschalten heisst conntrack leeren.** `delete table` allein laesst laufende Streams bis zum
Timeout weiterlaufen. Der Selektor ist die *originale* Zieladresse (das Gateway, nicht der
Sunshine-Host) und **pro Port** — `conntrack -D -d <gateway>` ohne Port reisst auch SSH ab.

**Rule-Comments sind eine API.** `internal/metrics` summiert ueber `LabelFwdTCP`,
`LabelFwdUDP` und `LabelFwdReply`; ein umbenannter Kommentar leert still die Grafik.

**Der Passwort-Hash darf kein `$` enthalten.** Er steht in `.env`, das Docker Compose auch
zur Interpolation liest — `$xyz` wird dort zum Leerstring, der Container bekaeme einen
abgeschnittenen Hash und jede Anmeldung scheitert ohne Meldung. Format ist deshalb
`pbkdf2-sha256.<Runden>.<Salt>.<Key>` mit URL-sicherem base64; ein Regressionstest prueft
die Zeichenklasse.

**Zustand ist Absicht, nicht Vollzug.** Reihenfolge immer: validieren → persistieren →
anwenden. Schlaegt das Anwenden fehl, wird *nicht* zurueckgerollt; der Fehler wird gemeldet
und die Health-Pruefung „Regelwerk" zeigt die Abweichung. Callers haben vorher schon
persistiert und geloggt.

**Port 47990 wird nie weitergeleitet** — Sunshines eigenes Web-Interface.

**Keine externen Go-Abhaengigkeiten.** Bewusst: der Image-Build zieht ausser den Basis-Images
nichts aus dem Netz. PBKDF2, Termios und der JUnit-Writer sind deshalb selbst geschrieben.
Eine neue Dependency ist eine Architekturentscheidung, kein Detail.

**Basis-Images haengen an Major-Tags** (`golang:1`, `alpine:3`), damit Updates von selbst
ankommen. Tragfaehig ist das nur durch die Tore: die Go-Suite faengt eine kaputte
Toolchain, die Dockerfile-Stage `smoke` ein umbenanntes Alpine-Paket. Die Tags stehen im
Dockerfile **und** im Jenkinsfile (URLTrigger auf `$.digest`) und muessen zusammen geaendert
werden.

## Grenzen der Entwicklungsumgebung

- **nftables-Syntax laesst sich hier nicht pruefen** (kein CAP_NET_ADMIN, und Paketquellen
  sind im Container blockiert). Neue Regeln gehen ueber `print-ruleset` und `make selftest`
  auf der VM gegen den echten Kernel. Syntax, die nicht laedt, legt die Weiterleitung lahm —
  im Zweifel optional machen oder mit Rueckfall bauen.
- **Die `apk`-Schritte im Dockerfile bauen hier nicht.** Bis `--target verified` bzw.
  `--target build` laeuft alles; die Laufzeit-Stufen erst auf einer Maschine mit
  Paketquellen.
- **Host-Sysctls sind aus dem Container nicht setzbar** (`ip_forward`,
  `nf_conntrack_acct`, `rp_filter`): stehen in `host-setup/99-sunshine-gw.conf` und werden
  von den Health-Checks gemeldet, nicht repariert.

## CI

`Jenkinsfile` baut `ruepp/sunshine-gw` fuer amd64 und arm64, jede Architektur nativ auf
ihrem Agenten, Push per Digest ohne Tag; `scripts/docker_manifest.sh` fuegt die Digests zu
einer Manifest-Liste zusammen, und erst die bekommt einen Tag.

Die Tests sitzen **im Image-Build**: Stage `test` (gofmt, vet, `go test -race`),
`test-results` exportiert den JUnit-Report auch bei roter Suite, `verified` verweigert
danach die Weiterarbeit, und die Laufzeit-Stufe stammt von `verified` ab — ein Image aus
durchgefallenem Code ist nicht baubar. Der Agent braucht nur Docker.

Die JS-Zeichenlogik ist **nicht** in der CI (dafuer waere ein Node-Toolchain im Image noetig):
`make check-chart` und danach einmal in den Browser schauen.

## Sprache

Alles, was der Nutzer sieht — UI-Texte, Log- und Fehlermeldungen — ist **deutsch**, und
zwar **durchgaengig ASCII**: `ue` statt `ü`, damit nichts an Terminals, in nft-Kommentaren
oder in Umgebungen mit anderer Locale kippt. Dasselbe gilt fuer die Textdateien des Repos
(README, diese Datei). Pruefen mit `grep -rnP "[\\x{00e4}\\x{00f6}\\x{00fc}\\x{00df}]" .`
(der Ausdruck ist absichtlich in Hex geschrieben): der einzige Treffer ist das Beispiel drei
Zeilen weiter oben, und dabei soll es bleiben.

**Code-Kommentare sind englisch** und begruenden das *Warum*, nicht das Was. Die
verdichteten Begruendungen an den heiklen Stellen — Hook-Prioritaeten, Regelreihenfolge,
Zaehler-Resets, warum eine Abhaengigkeit fehlt — sind die eigentliche Dokumentation dieses
Projekts; wer dort etwas aendert, aktualisiert sie mit.
