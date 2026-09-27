#!/bin/sh
# Runs INSIDE the image build (Dockerfile stage `test`), not on a Jenkins agent.
#
# Deliberately never fails: the `test-results` target has to export a JUnit report even
# for a red suite, otherwise Jenkins has nothing to publish and the build log is the only
# record of what broke. The verdict is written to $OUT/exit-code, and the Dockerfile's
# `verified` stage is what refuses to build an image from it.
set -u

OUT="${1:-/out}"
mkdir -p "${OUT}"
status=0

echo "== gofmt"
unformatted="$(gofmt -l .)"
if [ -n "${unformatted}" ]; then
    echo "nicht formatiert:" >&2
    echo "${unformatted}" >&2
    status=1
else
    echo "ok"
fi

echo "== go vet"
if ! go vet ./...; then
    status=1
fi

# -race needs cgo and a C compiler, which is why the builder stage is the Debian-based
# golang image rather than the alpine one. Data races in the scheduler or the status
# cache are exactly the kind of bug that would otherwise only show up in production.
echo "== go test -race"
if ! go test -race -count=1 -json ./... > "${OUT}/events.json"; then
    status=1
fi

echo "== JUnit-Report"
go build -o /tmp/junitreport ./cmd/junitreport
if ! /tmp/junitreport < "${OUT}/events.json" > "${OUT}/tests.junit.xml"; then
    echo "Report konnte nicht erzeugt werden" >&2
    status=1
fi
rm -f "${OUT}/events.json"

printf '%s\n' "${status}" > "${OUT}/exit-code"
echo "== Ergebnis: ${status} (0 = alles gruen)"
exit 0
