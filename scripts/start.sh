#!/bin/bash
set -euo pipefail

# The build context is the repository root and so are the Dockerfile, the metadata file and the
# digest file the Jenkinsfile stashes. Resolved once here so this also works run by hand from
# another directory, not just from the workspace root Jenkins checks out into.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

echo "Starting build workflow"

# shellcheck source=scripts/docker_platforms.sh
. "${ROOT}/scripts/docker_platforms.sh"
# shellcheck source=scripts/docker_tags.sh
. "${ROOT}/scripts/docker_tags.sh"

"${ROOT}/scripts/docker_initialize.sh"

# Run the suite first and export the JUnit report, so Jenkins has something to publish even when
# the image build below refuses to proceed. This stage is cached, so the image build does not
# repeat it.
"${ROOT}/scripts/test.sh"

# One image, one architecture — pushed by digest, deliberately without a tag.
#
# The obvious alternative is a tag per architecture, joined afterwards. It works, but every build
# then leaves `<tag>-amd64` and `<tag>-arm64` behind in the registry forever: half-images nobody
# should pull, cluttering the tag list users actually read. push-by-digest uploads the same manifest
# and simply does not name it; the manifest list written by scripts/docker_manifest.sh is what
# references it, and that is the only thing that ends up with a tag.
#
# The cost is that the digest has to travel to the machine writing the manifest, which is what the
# Jenkinsfile's stash of the file below is for.
ARCH="${HOST_PLATFORM#linux/}"
METADATA_FILE="build-metadata-${ARCH}.json"
DIGEST_FILE="digest-${ARCH}.txt"

echo "[${BRANCH_NAME:-local}] Building ${IMAGE_REPO} for ${BASE_TAG} natively on ${HOST_PLATFORM}"

# VCS_REF lands in the binary (-X main.version) and in the image labels, so a running
# gateway and `docker inspect` both say which commit they came from. GIT_COMMIT is set by
# Jenkins; a run by hand falls back to git, and to "unknown" outside a checkout.
VCS_REF="${GIT_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

docker buildx build \
    --platform "${RESOLVED_PLATFORMS}" \
    --output "type=image,name=${IMAGE_REPO},push-by-digest=true,name-canonical=true,push=true" \
    --metadata-file "${METADATA_FILE}" \
    --build-arg "VCS_REF=${VCS_REF}" \
    --build-arg "BUILD_DATE=${BUILD_DATE}" \
    --pull \
    .

# BuildKit reports the pushed manifest's digest in the metadata file, and that digest is the only
# handle on an image that carries no tag.
#
# Parsed with sed rather than jq: the agent needs Docker and nothing else, and adding a dependency
# to read one string would undo that. The pattern is anchored on the key, and the result is checked
# below — a silent empty digest would otherwise surface much later as an unreadable imagetools error.
DIGEST="$(sed -n 's/.*"containerimage.digest"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    "${METADATA_FILE}")"
DIGEST="${DIGEST%%$'\n'*}"

case "${DIGEST}" in
    sha256:*)
        ;;
    *)
        echo "ERROR: no image digest in ${METADATA_FILE}. BuildKit wrote:" >&2
        cat "${METADATA_FILE}" >&2
        exit 1
        ;;
esac

printf '%s\n' "${DIGEST}" > "${DIGEST_FILE}"
echo "Pushed ${IMAGE_REPO}@${DIGEST} (${HOST_PLATFORM}, untagged)"

# No cleanup here.
#
# The Jenkinsfile calls scripts/docker_cleanup.sh once per architecture stage instead, from a post
# block that runs even when this build failed.
