# Build: a static binary, no cgo, no dependencies beyond the standard library.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/gateway ./cmd/gateway

# Runtime: the control plane plus the three tools it drives. Packets are forwarded by
# the kernel, so nothing here sits in the data path.
FROM alpine:3.22
RUN apk add --no-cache nftables iptables conntrack-tools
COPY --from=build /out/gateway /usr/local/bin/gateway
VOLUME /data
ENV GW_STATE=/data/config.json
# Runs as root on purpose: nft and iptables need CAP_NET_ADMIN, and a capability
# without file capabilities is only effective for uid 0.
ENTRYPOINT ["/usr/local/bin/gateway"]
