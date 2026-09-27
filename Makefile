BIN := gateway
GO  := docker run --rm -v "$(CURDIR)":/src -w /src --user "$$(id -u):$$(id -g)" \
        -e HOME=/tmp -e GOCACHE=/tmp/gocache golang:1.25-alpine go

.PHONY: test vet build image up down logs restart selftest hash ruleset clean

test:            ## Unit-Tests
	$(GO) test ./...

vet:
	$(GO) vet ./...

build: vet test   ## statisches Binary nach ./$(BIN)
	$(GO) build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/gateway

image:            ## Container-Image bauen
	docker compose build

up: image         ## starten
	docker compose up -d

down:             ## stoppen (entfernt auch die Weiterleitung)
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f --tail=50

selftest:         ## Voraussetzungen und Ruleset auf diesem Rechner pruefen
	./scripts/selftest.sh

hash:             ## Passwort-Hash fuer GW_PASSWORD_HASH erzeugen
	docker compose run --rm sunshine-gateway hash-password

ruleset:          ## gerendertes nftables-Ruleset anzeigen
	docker compose exec sunshine-gateway gateway print-ruleset

clean:
	rm -f $(BIN)
