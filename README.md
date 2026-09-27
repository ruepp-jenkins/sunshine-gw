# Sunshine Gateway

Ein schaltbares Weiterleitungs-Gateway zwischen FRITZ!Box und Sunshine-Server, mit
kleinem Web-Interface: Zieladresse einstellen, Weiterleitung an- und abschalten, und
jeden Tag zu einer festen Uhrzeit automatisch abschalten lassen.

Die FRITZ!Box bekommt **einmalig per GUI** eine permanente Portfreigabe auf dieses
Gateway. Ob und wohin es weitergeht, entscheidet ab dann das Gateway. Kein TR-064,
kein UPnP, keine selbstaendigen Portfreigaben.

```
   Internet ──▶ FRITZ!Box ──▶ Gateway (dieser Container) ──▶ Sunshine-Server
                (permanente      nftables DNAT im Kernel        z.B. 10.10.10.5
                 Freigabe)       z.B. 10.10.10.20
```

## Warum kein nginx und kein haproxy

* **haproxy kann kein UDP.** Sunshines Video, Audio und Input laufen ueber UDP
  47998-48000 - damit ist haproxy fuer den Stream unbrauchbar.
* **nginx `stream` kann UDP, ist aber der falsche Layer.** Jedes Paket laeuft
  Kernel → Userspace → Kernel, wird kopiert und wartet auf einen Scheduling-Slot. Das
  erzeugt Jitter, und genau darauf reagiert Moonlight mit Frame-Drops. Dazu behandelt
  nginx UDP als Session mit `proxy_timeout`, was bei Dauerlast zu Session-Churn fuehrt.
* **Dieses Gateway leitet im Kernel weiter.** Nur das erste Paket eines Flows laeuft
  durch die NAT-Chain, danach macht conntrack einen Hash-Lookup im Forwarding-Pfad.
  Paketgrenzen und -groessen bleiben 1:1 erhalten, was bei Sunshines ~1400-Byte-
  Video-Paketen auf MTU-Kante zaehlt. Der Container sieht kein einziges Paket: er
  rendert nur das Regelwerk. Ein Absturz oder Neustart des Prozesses kann einen
  laufenden Stream nicht abreissen.

## Wo das laufen sollte

Eine eigene kleine VM, nicht der Docker-Host, auf dem noch anderes laeuft: der
Container braucht `network_mode: host` und `NET_ADMIN` und schreibt damit in das
Firewall-Regelwerk der Maschine. Ausserdem ist das hier das einzige Geraet, auf das
aus dem Internet gezeigt wird.

* Proxmox-VM, Debian 13 minimal, 1 vCPU, 512 MB-1 GB, virtio-net, **feste IP**
* Docker und Docker Compose
* LXC geht auch, verlangt aber `nf_conntrack`/`nf_nat` auf dem Proxmox-Host und
  `nesting=1` fuer Docker-in-LXC - mehr Fehlerquellen fuer keinen messbaren Gewinn

## Installation

```sh
# 1. Host-Voraussetzung: der Kernel muss weiterleiten duerfen
sudo cp host-setup/99-sunshine-gw.conf /etc/sysctl.d/99-sunshine-gw.conf
sudo sysctl --system

# 2. Konfiguration
cp .env.example .env
$EDITOR .env            # GW_LISTEN auf die LAN-Adresse dieser Maschine setzen

# 3. Image holen und Passwort setzen
docker compose pull     # oder: docker compose build  (baut inkl. Testsuite lokal)
docker compose run --rm sunshine-gw hash-password
# Passwort wird zweimal abgefragt und nicht angezeigt; ausgegebene Zeile nach
# GW_PASSWORD_HASH in .env kopieren. Fuer ein Skript geht auch:
#   printf '%s' 'geheim' | docker compose run --rm -T sunshine-gw hash-password

# 4. starten
docker compose up -d
docker compose logs -f
```

Aktualisieren spaeter: `docker compose pull && docker compose up -d`. Jenkins baut
`ruepp/sunshine-gw` fuer amd64 und arm64, `docker pull` waehlt die passende Architektur.

Web-Interface dann auf `http://<GW_LISTEN>` - Benutzer aus `GW_USER`, Passwort das
gerade gehashte. Dort Zieladresse eintragen, speichern, einschalten.

### Portfreigabe in der FRITZ!Box

Einmal per GUI anlegen, Ziel ist die **Gateway-IP**:

| Port | Protokoll | Zweck |
|------|-----------|-------|
| 47984 | TCP | HTTPS / GameStream |
| 47989 | TCP | HTTP / GameStream |
| 48010 | TCP | RTSP |
| 47998-48000 | UDP | Video, Audio, Control |
| 48002 | UDP | Mic (ungenutzt, der Vollstaendigkeit wegen) |

**47990 nicht freigeben** - das ist Sunshines eigenes Web-Interface und hat im
Internet nichts zu suchen.

Die Regel darf dauerhaft stehen bleiben. Ist die Weiterleitung aus, verwirft das
Gateway diese Ports still (eigene nftables-Tabelle `sunshine_gw_guard`), von aussen
sieht die Freigabe also aus wie ein schwarzes Loch und nicht wie ein geschlossener
Port.

## Bedienung

Das Web-Interface hat genau eine Seite:

* **Ein/Aus** - der grosse Knopf. Beim Abschalten werden zusaetzlich die
  conntrack-Eintraege der weitergeleiteten Flows geloescht, sonst liefe ein aktiver
  Stream bis zum Timeout weiter. Erst damit ist es ein Kill-Switch.
* **Zieladresse** - IPv4 des Sunshine-Rechners.
* **Taegliche Abschaltung** - Uhrzeit in der eingestellten Zeitzone; leer schaltet den
  Zeitplan ab. Faellt die Uhrzeit an, waehrend das Gateway aus war, wird beim Start
  nachgeholt: ein Neustart um 2 Uhr nachts laesst die Freigabe nicht bis zum naechsten
  Tag offen.
* **Nur externe Quellen** - Pakete aus dem LAN werden nicht weitergeleitet; LAN-Clients
  sprechen Sunshine direkt an. Zum Testen von innen ueber die eigene WAN-Adresse
  (Hairpin-NAT) muss das aus.
* **Fast-Path** - optionale nftables-flowtable. Schleust etablierte Flows an der
  Netfilter-Kette vorbei; messbar nur unter Last, bei Problemen einfach wieder aus.
* **Zaehler und Pruefungen** - zeigen, ob Pakete ankommen und ob die Voraussetzungen
  am Host stimmen (ip_forward, FORWARD-Policy, conntrack, Erreichbarkeit des Ziels).

## Wer nutzt das Gateway

Das Web-Interface zeigt den Durchsatz der letzten halben Stunde als Grafik (hoch und
runter getrennt) und darunter eine Tabelle der Clients: Adresse, aktiv oder beendet,
Anzahl Flows, bewegte Datenmengen, Anzahl Sitzungen, letzter Kontakt. Der Verlauf
ueberlebt einen Neustart (`/data/metrics.json`) und laesst sich mit einem Knopf loeschen.

**Das kostet keine Latenz, weil nichts davon im Datenpfad liegt.** Beide Quellen sind
Zustand, den der Kernel ohnehin fuehrt:

* **Durchsatz** aus den Zaehlern der Forward-Kette. Die stehen in den Regeln, die es fuer
  die Weiterleitung sowieso gibt - ein Zaehler ist ein Inkrement auf einer Cache-Zeile,
  die das Paket gerade anfasst.
* **Adressen und Datenmengen** aus conntrack. Jede weitergeleitete Verbindung hat dort
  einen Eintrag, sonst koennte der Kernel die Uebersetzung nicht machen; die Quelladresse
  darin ist die echte Adresse des Clients im Internet.

Ein Sampler liest beides alle fuenf Sekunden - zwei kurzlebige Kommandos, rund 0,2 % einer
CPU auf der VM, und **niemals ein Paket**. Das ist der entscheidende Unterschied zu jeder
Form von Mitschnitt: ein Userspace-Proxy, ein Port-Mirror oder pcap wuerden Latenz und
Jitter kosten, genau das, worauf Moonlight reagiert. Deshalb gibt es hier auch keine
Per-Paket-Statistik und keine Protokollanalyse: der Preis dafuer waere der, den das ganze
Projekt vermeiden soll.

Fuer die Datenmengen pro Client muss `net.netfilter.nf_conntrack_acct=1` gesetzt sein
(steht in `host-setup/99-sunshine-gw.conf`, im Container nicht setzbar). Fehlt es, sagt
das die Pruefliste, und die Tabelle zeigt Adressen und Flows ohne Volumen.

Was die Zahlen **nicht** sagen: wer jemand ist. Sichtbar ist die Adresse, mit der das
Paket ankam - bei Mobilfunk das Carrier-NAT, nicht das Geraet. Und durch das Masquerade
sieht Sunshine selbst alle externen Clients als Gateway-IP; wer Sunshines eigene Logs
liest, findet dort keine Client-Adressen mehr. Diese Tabelle ist die einzige Stelle, an
der sie stehen.

## Passwort und Hash-Format

`hash-password` erzeugt `pbkdf2-sha256.<Runden>.<Salt>.<Key>` mit 210000 Runden und
URL-sicherem base64. Separator und Alphabet sind bewusst nicht das ueblichere
PHC-Format mit `$` und Standard-base64: `.env` wird von Docker Compose auch zur
Variablen-Interpolation gelesen, und `$irgendwas` darin gilt als Variablenreferenz —
Compose warnt einmal und setzt einen Leerstring ein. Der Container bekaeme einen
abgeschnittenen Hash, und jede Anmeldung wuerde ohne erkennbaren Grund scheitern. So wie
es jetzt ist, passt der Hash in `.env`, YAML und Shell ohne Anfuehrungszeichen.

Ein unbrauchbarer Hash laesst das Gateway beim Start mit Begruendung abbrechen, statt
jeden Anmeldeversuch stumm mit 401 zu beantworten.

## Verifikation

### Regelwerk und Datenpfad

```sh
make selftest                  # Ruleset gegen den echten Kernel pruefen, Voraussetzungen
docker compose exec sunshine-gw nft list table inet sunshine_gw
```

Moonlight von aussen verbinden (Handy im Mobilfunk), waehrend des Streams erneut
`nft list table inet sunshine_gw`: die Zaehler der UDP-Regeln laufen hoch. Im
Web-Interface ist dasselbe sichtbar, inklusive Anzahl aktiver Verbindungen.

### Warum ein Test aus dem eigenen LAN nichts beweist

Moonlight merkt sich pro gekoppeltem Rechner **mehrere** Adressen - local, manual, IPv6,
remote - und probiert sie bei jedem Poll in dieser Reihenfolge durch; die erste, die
antwortet, wird benutzt. Die direkte Adresse des Sunshine-Rechners lernt es dabei von
selbst, per mDNS-Discovery im LAN. Gekoppelte Rechner werden ueber Sunshines UUID
identifiziert, nicht ueber die Adresse: Gateway-Pfad und direkt gefundener Rechner sind
derselbe Eintrag, und es gibt keinen Schalter, der Moonlight auf eine Adresse festnagelt.

Aus dem LAN ist der direkte Weg erreichbar, also wechselt Moonlight beim naechsten Poll -
typischerweise direkt nach dem Beenden eines Streams - darauf zurueck. Das ist gewolltes
Client-Verhalten und am Gateway nicht behebbar: dazu muesste man Sunshines serverinfo
umschreiben, also die per Client-Zertifikat geschuetzte HTTPS-Verbindung auf 47984
aufbrechen, was das Pairing zerstoert. Von aussen ist der direkte Weg nicht erreichbar,
dort bleibt es beim Gateway - und das ist der Fall, auf den es ankommt.

Sauber pruefen lassen sich drei Wege:

1. **Von aussen, ueber Mobilfunk.** Das echte Szenario, und das einzige, das auch
   „nur externe Quellen" mitprueft.
2. **Direkten Weg auf dem Test-Client sperren**, z.B. unter Linux
   `sudo ip route add blackhole <sunshine-ip>/32`, unter Windows eine Firewall-Regel.
   Moonlight findet den Rechner dann weiter per mDNS, kommt aber nicht durch und faellt
   auf die manuell eingetragene Gateway-Adresse zurueck.
3. **Test-Client in ein anderes Subnetz/VLAN**, dessen Adressen ausserhalb des
   eingetragenen LAN-Netzes liegen - dann greift auch „nur externe Quellen" wie im
   Ernstfall.

Mit eingeschaltetem „nur externe Quellen" ist ein Test aus dem LAN ueber die
Gateway-Adresse ohnehin blockiert, und zwar absichtlich. Wer es zum Testen ausschaltet,
sollte es danach wieder einschalten.

```sh
docker compose exec sunshine-gw conntrack -L -d <GATEWAY_IP>
```

### Kill-Switch

1. Bei laufendem Stream im UI auf **Jetzt abschalten**: die Verbindung muss innerhalb
   von Sekunden abreissen, nicht erst nach dem conntrack-Timeout.
2. Danach ist `conntrack -L -d <GATEWAY_IP>` fuer diese Ports leer.
3. Von aussen (nicht aus dem eigenen LAN) im Aus-Zustand:
   `nmap -Pn -p 47984,47989,48010 <WAN_IP>` → `filtered`, nicht `closed`. `closed`
   wuerde bedeuten, dass die Blackhole-Tabelle fehlt.

### Latenz - die eigentliche Anforderung

1. **Referenz:** Moonlight-Overlay-Statistik (Network Latency) vom selben Client,
   einmal direkt gegen Sunshine, einmal ueber das Gateway. Die Differenz soll in der
   Messstreuung liegen (< 1 ms).
2. **Jitter:** `iperf3 -s` auf dem Sunshine-Host, dann vom Client
   `iperf3 -u -b 50M -t 30 -c <ZIEL>` direkt und ueber das Gateway. Jitter und Loss
   vergleichen - das ist die Zahl, an der ein Userspace-Proxy auffliegen wuerde.
3. `mtr <ZIEL>` zur Kontrolle, dass genau ein Hop dazukommt.

### Zeitplan

1. Abschaltzeit zwei Minuten in die Zukunft setzen, warten: die Weiterleitung geht
   aus, im Verlauf steht der Grund.
2. **Nachholen:** einschalten, Abschaltzeit auf eine gerade vergangene Uhrzeit setzen,
   `docker compose restart` → das Gateway kommt ausgeschaltet hoch.
3. Im Ein-Zustand `docker compose restart` → Regelwerk ist danach wieder geladen.

### Pruefungen

```sh
sudo sysctl -w net.ipv4.ip_forward=0      # UI muss warnen und die Ursache nennen
sudo sysctl -w net.ipv4.ip_forward=1
```

Zieladresse auf eine unbenutzte IP setzen → Warnung „antwortet nicht" statt still
kaputter Weiterleitung.

## Was im Kernel passiert

Zwei eigene nftables-Tabellen, die keine andere Firewall anfassen:

* `inet sunshine_gw` - existiert nur bei eingeschalteter Weiterleitung.
  * `prerouting` (nat, dstnat): Pakete an die Gateway-Adresse auf den freigegebenen
    Ports werden auf das Ziel umgeschrieben. Erkennungsmerkmal ist `ip daddr <Gateway>` -
    das Gateway hat keine WAN-Seite, weitergeleitete Pakete kommen ueber dasselbe
    Interface wie alles andere.
  * `postrouting` (nat, srcnat): `masquerade` fuer genau diese Flows (`ct status dnat`).
    Notwendig, weil der Sunshine-Rechner seine Default-Route auf die FRITZ!Box hat -
    ohne SNAT gingen die Antwortpakete am Gateway vorbei. Sunshine sieht externe
    Clients dadurch als Gateway-IP; Moonlight-Pairing laeuft ueber Client-Zertifikate,
    nicht ueber IP-Adressen.
  * `forward` (filter, policy accept): erlaubt und zaehlt die Flows.
* `inet sunshine_gw_guard` - immer geladen, verwirft die freigegebenen Ports am Gateway
  selbst. Bei eingeschalteter Weiterleitung stoert das nicht: DNAT im prerouting-Hook
  schickt diese Pakete in den forward-Hook, nie in den input-Hook. Die Tabelle hat zwei
  Formen: **im Aus-Zustand** kommt eine Kette im `raw`-Hook dazu (Prioritaet -300), die vor
  conntrack (-200) verwirft. Ohne sie legt jedes Paket aus dem Internet erst einen
  conntrack-Eintrag an, bevor der input-Hook es wegwirft - bei dauerhaft stehender
  FRITZ!Box-Freigabe kann so jeder von aussen Zustand im Gateway erzeugen und mit
  wechselnden Quellports `nf_conntrack_max` fuellen. **Im Ein-Zustand** darf diese Kette
  nicht existieren, weil `raw` vor `dstnat` laeuft und genau die Pakete verwerfen wuerde,
  die uebersetzt werden sollen; bleibt sie versehentlich stehen, meldet die Pruefliste das
  als Fehler.

Angewendet wird immer das komplette gerenderte Ruleset in einer Transaktion
(`table`/`delete table`/neu definieren), damit es keinen Zwischenzustand gibt.

### Was der Aus-Zustand garantiert

Dass im Aus-Zustand nichts weitergeleitet wird, ist keine Frage einer Regel, die alles
abfaengt, sondern **strukturell**: ein Paket, das die FRITZ!Box weitergeleitet hat, kommt
an die Adresse des Gateways adressiert an. Weiterleiten kann der Kernel nur, was *woanders*
hin adressiert ist - und die einzige Stelle, die das Ziel umschreiben wuerde, ist die
DNAT-Regel. Ist die Tabelle geloescht, gibt es diese Regel nicht, das Paket bleibt an das
Gateway adressiert, geht damit in den input-Hook statt in den forward-Hook und wird dort
von der Blackhole-Tabelle verworfen. Der forward-Hook wird gar nicht erreicht.

Drei Dinge muessten also liegen bleiben, damit dieses Argument faellt, und genau die
pruefte das Web-Interface im Aus-Zustand unter „Aus-Zustand":

1. die Tabelle `inet sunshine_gw` (waere die DNAT-Regel),
2. die Kette `SUNSHINE-GW` in `DOCKER-USER` (waere die Forward-Freigabe),
3. conntrack-Eintraege auf den freigegebenen Ports (waeren laufende Streams, die
   unabhaengig von den Regeln weiter uebersetzt wuerden).

Alle drei werden beim Abschalten entfernt; steht trotzdem etwas davon, sagt die Pruefung
das als Fehler, statt es zu verschweigen. Selbst nachsehen:

```sh
docker compose exec sunshine-gw nft list ruleset | grep -c dnat        # muss 0 sein
docker compose exec sunshine-gw iptables -w 5 -S SUNSHINE-GW           # nur die Kette, keine Regeln
docker compose exec sunshine-gw conntrack -L -d <GATEWAY_IP> 2>/dev/null | grep -E 'dport=(47984|47989|48010|4799[89]|4800[02])'
nmap -Pn -p 47984,47989,48010 <WAN_IP>                                 # von aussen: filtered
```

Was dabei ehrlich dazugehoert - und was „aus" **nicht** heisst:

* **Das Gateway empfaengt weiter.** Die Portfreigabe in der FRITZ!Box steht dauerhaft, also
  treffen Pakete aus dem Internet weiter auf den Kernel des Gateways; sie werden verworfen,
  aber sie kommen an. Dem Sunshine-Rechner kann nichts passieren, dem IP-Stack des Gateways
  steht der Verkehr offen. Deshalb faellt die Entscheidung im Aus-Zustand so frueh wie
  moeglich, im `raw`-Hook vor conntrack: kein Zustand, keine Policy-Auswertung, ein
  Zaehler und weg. Ein Rest bleibt trotzdem - IP- und L4-Header werden geparst, bevor die
  Regel greift. Nur ein Abschalten der Freigabe in der Box selbst waere wirklich nichts.
* **„Aus" ist ein Software-Zustand, keine gezogene Leitung.** Wer das Web-Interface
  erreicht und das Passwort hat, schaltet ein - oder wer root auf dem Gateway hat. Die
  Zusage lautet „solange aus ist, wird nichts weitergeleitet", nicht „es kann nie wieder
  weitergeleitet werden". Darum gehoert das UI an eine LAN-Adresse und hinter ein Passwort.


* **Ports, die das Gateway nicht kennt.** Die Blackhole-Tabelle verwirft genau die
  konfigurierten Ports. Gibt die FRITZ!Box einen Port frei, der in der Portliste nicht
  steht, wird er nicht weitergeleitet - aber der Kernel antwortet mit RST bzw. ICMP
  unreachable, statt zu schweigen. Beide Listen gehoeren deshalb zusammen gepflegt.
* **ip_forward bleibt an**, das Gateway ist weiter ein Router fuer das LAN. Von aussen
  nutzt das nichts, weil die FRITZ!Box nur Pakete an die Gateway-Adresse hereingibt; ein
  LAN-Geraet koennte darueber routen, kaeme aber auch direkt an den Sunshine-Rechner.
* **Ein hart abgeschossener Container.** Bei `docker compose down` oder `stop` raeumt das
  Gateway die Regeln selbst weg (SIGTERM). Bei SIGKILL oder Stromausfall bleiben sie
  geladen, und niemand haelt dann die taegliche Abschaltzeit ein - bis `restart:
  unless-stopped` den Container zurueckbringt. Ein Reboot loescht das Regelwerk ohnehin,
  nftables ist nicht persistent.

**Docker setzt die iptables-FORWARD-Policy auf DROP.** Ein `accept` in einer eigenen
nft-Tabelle hebt das nicht auf: jede Tabelle wird fuer den Hook ausgewertet, und ein
einziges `drop` gewinnt. Deshalb pflegt das Gateway zusaetzlich eine Kette
`SUNSHINE-GW`, die aus `DOCKER-USER` gesprungen wird - ein `ACCEPT` dort beendet die
FORWARD-Traversierung. Fehlt `DOCKER-USER` (Docker im nftables-Modus), sagt das die
Pruefung im UI.

## Grenzen

* **IPv4.** Die Portfreigabe der FRITZ!Box und Moonlight laufen hier ueber IPv4;
  IPv6-Weiterleitung ist nicht implementiert.
* **Masquerade** heisst: Sunshine sieht externe Clients mit der Gateway-IP, also mit
  einer LAN-Adresse - und ordnet sie damit als LAN-Clients ein. Das hat eine Folge, die
  man kennen muss: Sunshines `lan_encryption_mode` steht per Default auf `0` (keine
  Verschluesselung), `wan_encryption_mode` auf `1`. Ueber dieses Gateway greift immer der
  LAN-Wert, Internet-Streams liefen also unverschluesselt, obwohl Sunshines
  WAN-Voreinstellung sie verschluesselt haette. Wer das nicht will, setzt in Sunshine
  **`lan_encryption_mode = 1`** (oder `2`, dann werden Clients ohne Verschluesselung
  abgewiesen). Aus demselben Grund gilt `origin_web_ui_allowed = lan` fuer externe
  Clients - ein weiterer Grund, Port 47990 niemals freizugeben.

  Die Alternative waere, die Client-Adressen zu erhalten, statt zu maskieren. Das
  verlangt auf dem Sunshine-Rechner eine Route zurueck ueber das Gateway (im Zweifel: das
  Gateway als Default-Route), greift also tief in dessen Netzkonfiguration ein - deshalb
  hier nicht der Weg.
* Das Web-Interface spricht HTTP. Es gehoert an eine LAN-Adresse gebunden und nicht
  ins Internet; es ist nie ueber die weitergeleiteten Ports erreichbar.

## Build-Pipeline

`Jenkinsfile` baut `ruepp/sunshine-gw` fuer amd64 und arm64 - jede Architektur nativ auf
ihrem eigenen Agenten, weil Emulation den Go-Build und die Testsuite unnoetig langsam
macht. Beide pushen ihr Image ohne Tag, nur per Digest; `scripts/docker_manifest.sh` fuegt
die beiden Digests zu einer Manifest-Liste zusammen, und erst die bekommt einen Tag. Ein
Build, der vorher abbricht, hinterlaesst damit keinen halben Tag in der Registry.

**Die Tests sitzen im Image-Build.** Der Dockerfile-Stage `test` laeuft `gofmt`, `go vet`
und `go test -race`; `test-results` exportiert daraus den JUnit-Report (auch bei roter
Suite, sonst hat Jenkins nichts zu zeigen), und `verified` verweigert die Weiterarbeit,
wenn etwas rot war. Die Laufzeit-Stufe kopiert aus `build`, das von `verified` abstammt -
ein Image aus durchgefallenem Code ist damit nicht baubar. Der Agent braucht dafuer nur
Docker, keine Go-Installation.

`cmd/junitreport` wandelt `go test -json` in JUnit-XML um. Selbst geschrieben, damit das
Modul abhaengigkeitsfrei bleibt und der Build ausser den Basis-Images nichts aus dem Netz
zieht. Ein Paket, das nicht kompiliert, erzeugt keine Test-Events - dieser Fall wird zu
einem fehlschlagenden Testfall, sonst sahe ein kaputter Build nach "nichts zu tun" aus.

**Basis-Images haengen an den Major-Tags** (`golang:1`, `alpine:3`), damit Updates von
selbst ankommen; der URLTrigger im Jenkinsfile beobachtet dazu `$.digest` der beiden Tags
auf Docker Hub und baut neu, wenn sich einer bewegt. Tragfaehig ist das nur, weil jede
Stufe ein Tor hat: eine Go-Version, die den Code bricht, faellt durch die Suite, und ein
Alpine, das ein Paket umbenennt, faellt durch die Stage `smoke` (die prueft, dass `nft`,
`iptables` und `conntrack` im Laufzeit-Image existieren und die Binary dort laeuft). Ein
Go 2 oder Alpine 4 bleibt bewusst aussen vor - das soll ein Commit sein, keine Ueberraschung
um 3 Uhr nachts. Die Tags stehen im Dockerfile und im Jenkinsfile und muessen zusammen
geaendert werden.

Der Commit landet per `-X main.version` in der Binary und als OCI-Label im Image: die
Fusszeile des Web-Interfaces und `docker inspect` sagen beide, welcher Build laeuft.

## Entwicklung

```sh
make test        # Unit-Tests mit Race-Detector (im golang-Container, kein lokales Go noetig)
make vet
make build       # statisches Binary ./gateway
make ruleset     # gerendertes nftables-Ruleset des laufenden Containers ansehen
```

Aufbau: `cmd/gateway` verdrahtet, `cmd/junitreport` ist das CI-Hilfsmittel von oben,
`internal/config` haelt und persistiert den Zustand,
`internal/firewall` rendert und laedt das Regelwerk, `internal/control` haelt Zustand
und Kernel in Deckung, `internal/scheduler` ist die taegliche Abschaltung,
`internal/metrics` sammelt Durchsatz und Clients neben dem Datenpfad, `internal/web` ist
die eine Seite.

Die Zeichenlogik der Grafik (`internal/web/static/app.js`) ist nicht Teil der Go-Suite -
dafuer waere ein Node-Toolchain im Image-Build noetig. Sie wurde einmal gegen eine
DOM-Attrappe geprueft (Achsenrichtung, Begrenzung von Ausreissern, leere Messreihe,
fehlendes Accounting); wer daran etwas aendert, sollte im Browser nachsehen.
