# Multi-stage build with the test suite inside it, so the image cannot be built from code
# that does not pass: the runtime stage copies from `build`, which descends from
# `verified`, which refuses to proceed on a red suite. scripts/test.sh exports the JUnit
# report out of `test-results` before that, so Jenkins has a report either way.
#
# Base images are pinned to their MAJOR tag, not to a minor release: golang:1 follows every
# Go 1.x, alpine:3 every 3.x, so patches and minor releases arrive on their own and the
# URLTrigger in the Jenkinsfile turns them into a build. What stays excluded is the one kind
# of bump that is breaking by definition - a Go 2 or an Alpine 4 - which should be a
# deliberate commit rather than a surprise at 3am.
#
# Floating tags are only safe because nothing ships untested: a Go release that breaks the
# code fails the suite below, and an Alpine release that renames a package fails the `smoke`
# stage. Both mean a red build, never a broken published image.
#
# The tags here and the URLTrigger entries in the Jenkinsfile are one setting in two files.
ARG GO_IMAGE=golang:1
ARG RUNTIME_IMAGE=alpine:3

FROM ${GO_IMAGE} AS source
WORKDIR /src
ENV GOFLAGS=-mod=mod
# No go.sum: the module has no dependencies outside the standard library, so nothing is
# downloaded during the build.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

FROM source AS test
COPY scripts/image-tests.sh ./scripts/
RUN sh scripts/image-tests.sh /out

# Only the report leaves this build; `scratch` keeps the export to exactly those files.
FROM scratch AS test-results
COPY --from=test /out/tests.junit.xml /

FROM test AS verified
RUN status="$(cat /out/exit-code)"; \
    if [ "${status}" != "0" ]; then \
        echo "Tests oder statische Pruefungen fehlgeschlagen - es wird kein Image gebaut" >&2; \
        exit "${status}"; \
    fi; \
    echo "Tests bestanden"

FROM verified AS build
# The commit ends up in the binary, so a running gateway can say which build it is. Both
# arguments live in this stage and the next, never in `source` or `test`, so a new commit
# does not invalidate the test cache.
ARG VCS_REF=unknown
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VCS_REF}" \
        -o /out/gateway ./cmd/gateway

# Runtime: the control plane plus the three tools it drives. Packets are forwarded by the
# kernel, so nothing here sits in the data path.
FROM ${RUNTIME_IMAGE} AS runtime-base
RUN apk add --no-cache nftables iptables conntrack-tools
COPY --from=build /out/gateway /usr/local/bin/gateway

# The Go suite above runs in the builder and says nothing about this image. This stage is
# the only check that covers the runtime itself, which is what makes the floating alpine:3
# tag defensible: a renamed or dropped package, or a binary that will not execute here,
# fails the build instead of shipping.
#
# What cannot be checked here is the ruleset against the kernel - `nft -c` needs netlink,
# which a build does not have. scripts/selftest.sh does that on the gateway.
FROM runtime-base AS smoke
RUN set -eu; \
    for tool in nft iptables conntrack; do \
        command -v "${tool}" >/dev/null || { echo "FEHLT im Runtime-Image: ${tool}" >&2; exit 1; }; \
    done; \
    nft --version; \
    gateway print-ruleset -state /nonexistent.json -target 192.0.2.5 -gateway 192.0.2.1 > /tmp/smoke.nft; \
    grep -q "dnat ip to 192.0.2.5" /tmp/smoke.nft; \
    grep -q "sunshine_gw_guard" /tmp/smoke.nft; \
    rm -f /tmp/smoke.nft; \
    echo "Runtime-Image in Ordnung"

FROM smoke
ARG VCS_REF=unknown
ARG BUILD_DATE
LABEL org.opencontainers.image.title="sunshine-gw" \
      org.opencontainers.image.description="Schaltbares nftables-Gateway fuer Sunshine-Portfreigaben" \
      org.opencontainers.image.source="https://github.com/ruepp-jenkins/sunshine-gw" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT"
VOLUME /data
ENV GW_STATE=/data/config.json
# Runs as root on purpose: nft and iptables need CAP_NET_ADMIN, and a capability without
# file capabilities is only effective for uid 0.
ENTRYPOINT ["/usr/local/bin/gateway"]
