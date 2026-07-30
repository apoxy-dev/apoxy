#!/bin/bash
#
# Apoxy installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/apoxy-dev/apoxy/main/install.sh | bash

set -e

# GitHub's /releases/latest endpoint returns the most-recently-*published*
# release, not the highest version - a patch cut on an old branch (e.g.
# v0.11.26) would "win" over an already-shipped v0.20.0 just by being newer.
# Walk every non-draft, non-prerelease tag instead and pick the highest by
# semver.
function latest_apoxy_release_tag() {
  command -v jq >/dev/null 2>&1 || {
    echo "jq is required to resolve the latest Apoxy release. Please install jq and re-run." >&2
    exit 1
  }

  local page=1 tags=""
  while [ "$page" -le 10 ]; do
    local batch
    batch=$(curl -gfsSL "https://api.github.com/repos/apoxy-dev/apoxy/releases?per_page=100&page=${page}" \
            | jq -r '.[] | select(.draft == false and .prerelease == false) | .tag_name')
    [ -n "$batch" ] || break
    tags="${tags}${batch}"$'\n'
    page=$((page + 1))
  done
  printf '%s\n' "$tags" | grep -v '^$' | sort -V | tail -n1
}

function copy_binary() {
  USER=$(whoami)
  chmod +x apoxy
  if [[ ":$PATH:" == *":$HOME/bin:"* ]]; then
      if [ ! -d "$HOME/bin" ]; then
        mkdir -p "$HOME/bin"
      fi
      mv apoxy "$HOME/bin/apoxy"
  elif [[ "$USER" == "root" ]]; then
      echo "Installing Apoxy to /usr/local/bin as root"
      mv apoxy /usr/local/bin/apoxy
  else
      echo "Installing Apoxy to /usr/local/bin which is write protected"
      echo "If you'd prefer to install Apoxy without sudo permissions, add \$HOME/bin to your \$PATH and rerun the installer"
      sudo mv apoxy /usr/local/bin/apoxy
  fi
}

function install_apoxy() {
  echo "Resolving the latest Apoxy release..."
  VERSION=$(latest_apoxy_release_tag)
  if [[ -z "$VERSION" ]]; then
    echo "Could not determine the latest Apoxy release (GitHub API rate limit?)" >&2
    exit 1
  fi
  echo "Installing Apoxy $VERSION"

  if [[ "$OSTYPE" == "linux"* ]]; then
			# On Linux, "uname -m" reports "x86_64" on Intel/AMD 64 bit
			# machines, "aarch64" on ARM 64 bit machines, and armv7l on ARM
			# 32 bit machines like the Raspberry Pi. Map these to the arch
			# suffixes used in release asset names.
			# Note that we don't output an armv6 binary for now.
			case $(uname -m) in
					x86_64)  ARCH=amd64;;
					aarch64) ARCH=arm64;;
					armv7l)  ARCH=armv6;;
					*)       ARCH=$(uname -m);;
			esac
			set -x
			curl -fsSL https://github.com/apoxy-dev/apoxy/releases/download/$VERSION/apoxy-linux-$ARCH > apoxy
			copy_binary
  elif [[ "$OSTYPE" == "darwin"* ]]; then
			# On macOS, "uname -m" reports "arm64" on Apple Silicon machines
			# and "x86_64" on Intel machines; map the latter to the "amd64"
			# asset name.
			case $(uname -m) in
					x86_64) ARCH=amd64;;
					*)      ARCH=$(uname -m);;
			esac
			set -x
			curl -fsSL https://github.com/apoxy-dev/apoxy/releases/download/$VERSION/apoxy-darwin-$ARCH > apoxy
			copy_binary
  else
      set +x
      echo "The Apoxy installer does not work for your platform: $OSTYPE"
      echo ""
      echo "If you think your platform should be supported, please file an issue:"
      echo "https://github.com/apoxy-dev/apoxy/issues/new"
      echo "Thank you!"
      exit 1
  fi

  set +x
}

# so that we can skip installation in CI and just test the version check
if [[ -z $NO_INSTALL ]]; then
  install_apoxy
fi

echo "Apoxy installed!"
