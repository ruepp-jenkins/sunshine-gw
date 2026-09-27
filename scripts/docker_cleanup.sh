#!/bin/bash
set -e
echo "Cleanup docker"

BUILDER_NAME="${BUILDX_BUILDER_NAME:-mybuilder}"

# Never abort the pipeline over cleanup. By the time this runs the image is already pushed, and a
# failure to tidy up must not turn a successful build red.
set +e

# The build cache dominates disk usage, and a multi-platform build holds one set of layers per
# architecture.
docker buildx prune -a -f

# Remove the builder itself. It runs as a container (docker-container driver) and holds its own
# state volume, so leaving it behind on a shared agent accumulates both. The cost is one bootstrap
# on the next run; set BUILDX_KEEP_BUILDER=true to trade that disk for a faster start.
if [ "${BUILDX_KEEP_BUILDER}" != "true" ]; then
    docker buildx rm "${BUILDER_NAME}"
fi

# Drop dangling images and stopped containers left by the build.
docker image prune -f
docker container prune -f

set -e
echo "Cleanup finished"
