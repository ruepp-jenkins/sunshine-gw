#!/bin/bash
# Resolves the repository and tags this build publishes. Sourced, not executed.
#
# Inputs:
#   IMAGE_FULLNAME  repository stem, e.g. ruepp/loopdns
#
# Exports:
#   IMAGE_REPO   repository this build pushes to
#   BASE_TAG     the tag the finished manifest list carries
#   FINAL_TAGS   every tag the manifest list gets, space separated
#
# There is no per-architecture tag. Each architecture pushes by digest and the manifest list is the
# only thing that gets named, so the registry's tag list stays exactly as long as the number of
# releases — see scripts/start.sh for how the digest reaches the manifest step.
#
# DATESTAMP is computed once by the Jenkinsfile's Prepare stage and passed in, not recomputed here:
# two machines running `date` disagree across midnight and across time zones, and the manifest step
# would then look for a tag nobody wrote. The fallback below only serves a run started by hand.

: "${IMAGE_FULLNAME:?IMAGE_FULLNAME is not set}"

DATESTAMP="${DATESTAMP:-$(date +%Y%m%d)}"

# A slash is legal in a branch name and illegal in a tag, so `feature/x` would otherwise be pushed as
# a repository named after the branch's first segment rather than as a tag.
SAFE_BRANCH="$(echo "${BRANCH_NAME:-local}" | tr '/' '-')"

case "${BRANCH_NAME:-}" in
    master|main)
        IMAGE_REPO="${IMAGE_FULLNAME}"
        BASE_TAG="${DATESTAMP}"
        FINAL_TAGS="${BASE_TAG} latest"
        ;;
    *)
        IMAGE_REPO="${IMAGE_FULLNAME}-test"
        BASE_TAG="${SAFE_BRANCH}-${DATESTAMP}"
        FINAL_TAGS="${BASE_TAG}"
        ;;
esac

export IMAGE_REPO BASE_TAG FINAL_TAGS
