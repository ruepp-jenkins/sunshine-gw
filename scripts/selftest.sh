#!/bin/sh
# Prueft das Gateway auf dem Rechner, auf dem es laeuft: Ruleset-Syntax gegen den
# echten Kernel, Host-Voraussetzungen, geladener Zustand. Aendert nichts.
set -eu

SERVICE=${SERVICE:-sunshine-gw}
run() { docker compose exec -T "$SERVICE" "$@"; }

echo "== Ruleset-Syntax (nft -c, Trockenlauf im Kernel)"
if run sh -c 'gateway print-ruleset | nft -c -f -'; then
	echo "   OK"
else
	echo "   FEHLER: das gerenderte Ruleset wird vom Kernel nicht akzeptiert" >&2
	exit 1
fi

echo "== ip_forward"
run sh -c 'cat /proc/sys/net/ipv4/ip_forward' | grep -qx 1 &&
	echo "   OK (1)" ||
	echo "   FEHLT: auf dem Host setzen, siehe host-setup/99-sunshine-gw.conf" >&2

echo "== FORWARD-Policy"
run sh -c 'iptables -w 5 -n -L FORWARD | head -1' || true
run sh -c 'iptables -w 5 -S SUNSHINE-GW 2>/dev/null || echo "   Kette SUNSHINE-GW ist leer oder fehlt"'

echo "== geladene Tabellen"
run nft list tables

echo "== Zaehler"
run sh -c 'nft list table inet sunshine_gw 2>/dev/null | grep -E "counter|comment" || echo "   keine Weiterleitungsregeln geladen"'

echo "== aktive Flows"
run sh -c 'conntrack -L 2>/dev/null | grep -cE "dport=(47984|47989|48010|4799[89]|4800[02])" || true'

echo "== fertig"
