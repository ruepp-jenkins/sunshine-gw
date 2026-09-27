BIN   := gateway
IMAGE := ruepp/sunshine-gw:latest
GO  := docker run --rm -v "$(CURDIR)":/src -w /src --user "$$(id -u):$$(id -g)" \
        -e HOME=/tmp -e GOCACHE=/tmp/gocache golang:1 go

.PHONY: test vet build image pull up down logs restart selftest hash ruleset check-chart clean

test:            ## Unit-Tests, wie in der CI mit Race-Detector
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

build: vet test   ## statisches Binary nach ./$(BIN)
	$(GO) build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/gateway

image:            ## Image lokal bauen (mit Testsuite im Build), Tag wie in docker-compose.yml
	docker build -t $(IMAGE) .

pull:             ## von Jenkins veroeffentlichtes Image holen
	docker compose pull

up:               ## starten; holt das Image selbst, wenn es fehlt
	docker compose up -d

down:             ## stoppen (entfernt auch die Weiterleitung)
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f --tail=50

check-chart:      ## Zeichenlogik der Durchsatz-Grafik pruefen (nicht Teil der CI)
	docker run --rm -v "$(CURDIR)":/src -w /src --user "$$(id -u):$$(id -g)" \
		node:22-alpine node scripts/check-chart.js

selftest:         ## Voraussetzungen und Ruleset auf diesem Rechner pruefen
	./scripts/selftest.sh

hash:             ## Passwort-Hash fuer GW_PASSWORD_HASH erzeugen
	docker compose run --rm sunshine-gw hash-password

ruleset:          ## gerendertes nftables-Ruleset anzeigen
	docker compose exec sunshine-gw gateway print-ruleset

clean:
	rm -f $(BIN)
