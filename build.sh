#!/bin/bash

# Default build options
BUILD_TYPE="default"

# Parse command-line arguments
while getopts ":t:" opt; do
  case $opt in
    t) BUILD_TYPE="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
        exit 1
    ;;
  esac
done

# Shift arguments to remove processed options
shift $((OPTIND-1))

PACKAGE="github.com/apoxy-dev/apoxy"
VERSION="v$(git describe --tags --always --abbrev=0 --match='v[0-9]*.[0-9]*.[0-9]*' 2> /dev/null | sed 's/^.//')"
COMMIT_HASH="$(git rev-parse --short HEAD)"
BUILD_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')

DIRTY="$(git status --porcelain)"
if [ -n "${DIRTY}" ]; then
  COMMIT_HASH="${COMMIT_HASH}-dirty"
fi

if [ "${BUILD_TYPE}" == "debug" ]; then
  VERSION="${VERSION}-dev"
fi

LDFLAGS=(
  "-X '${PACKAGE}/build.BuildVersion=${VERSION}'"
  "-X '${PACKAGE}/build.BuildDate=${BUILD_TIMESTAMP}'"
  "-X '${PACKAGE}/build.CommitHash=${COMMIT_HASH}'"
)

echo "Building version ${VERSION} (${COMMIT_HASH})..."

go install -tags sqlite_enable_dbstat_vtab -ldflags="${LDFLAGS[*]}"

# Check if GOPATH is set
if [ -z "${GOPATH}" ]; then
    GOPATH=$(go env GOPATH)
fi

mv ${GOPATH}/bin/apoxy ${GOPATH}/bin/apoxy
