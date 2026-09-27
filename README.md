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

# 3. Passwort setzen
docker compose build
docker compose run --rm sunshine-gateway hash-password
# ausgegebenen Hash nach GW_PASSWORD_HASH in .env kopieren

# 4. starten
docker compose up -d
docker compose logs -f
```

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

## Verifikation

### Regelwerk und Datenpfad

```sh
make selftest                  # Ruleset gegen den echten Kernel pruefen, Voraussetzungen
docker compose exec sunshine-gateway nft list table inet sunshine_gw
```

Moonlight von aussen verbinden (Handy im Mobilfunk), waehrend des Streams erneut
`nft list table inet sunshine_gw`: die Zaehler der UDP-Regeln laufen hoch. Im
Web-Interface ist dasselbe sichtbar, inklusive Anzahl aktiver Verbindungen.

```sh
docker compose exec sunshine-gateway conntrack -L -d <GATEWAY_IP>
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
  schickt diese Pakete in den forward-Hook, nie in den input-Hook.

Angewendet wird immer das komplette gerenderte Ruleset in einer Transaktion
(`table`/`delete table`/neu definieren), damit es keinen Zwischenzustand gibt.

**Docker setzt die iptables-FORWARD-Policy auf DROP.** Ein `accept` in einer eigenen
nft-Tabelle hebt das nicht auf: jede Tabelle wird fuer den Hook ausgewertet, und ein
einziges `drop` gewinnt. Deshalb pflegt das Gateway zusaetzlich eine Kette
`SUNSHINE-GW`, die aus `DOCKER-USER` gesprungen wird - ein `ACCEPT` dort beendet die
FORWARD-Traversierung. Fehlt `DOCKER-USER` (Docker im nftables-Modus), sagt das die
Pruefung im UI.

## Grenzen

* **IPv4.** Die Portfreigabe der FRITZ!Box und Moonlight laufen hier ueber IPv4;
  IPv6-Weiterleitung ist nicht implementiert.
* **Masquerade** heisst: in Sunshines Logs erscheinen externe Clients mit der
  Gateway-IP.
* Das Web-Interface spricht HTTP. Es gehoert an eine LAN-Adresse gebunden und nicht
  ins Internet; es ist nie ueber die weitergeleiteten Ports erreichbar.

## Entwicklung

```sh
make test        # Unit-Tests (laufen in einem golang-Container, kein lokales Go noetig)
make vet
make build       # statisches Binary ./gateway
make ruleset     # gerendertes nftables-Ruleset des laufenden Containers ansehen
```

Aufbau: `cmd/gateway` verdrahtet, `internal/config` haelt und persistiert den Zustand,
`internal/firewall` rendert und laedt das Regelwerk, `internal/control` haelt Zustand
und Kernel in Deckung, `internal/scheduler` ist die taegliche Abschaltung,
`internal/web` ist die eine Seite.
