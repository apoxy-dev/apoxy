#!/usr/bin/env bash

set -euo pipefail

readonly schema="workerd.capnp"
readonly capnp_module="capnproto.org/go/capnp/v3"

if ! command -v capnp >/dev/null 2>&1; then
  echo "capnp is required to regenerate ${schema}" >&2
  exit 1
fi

module_dir="$(go list -m -f '{{.Dir}}' "${capnp_module}")"
tool_dir="$(mktemp -d)"
trap 'rm -rf "${tool_dir}"' EXIT

go build -o "${tool_dir}/capnpc-go" "${capnp_module}/capnpc-go"
PATH="${tool_dir}:${PATH}" capnp compile \
  -I "${module_dir}/std" \
  -ogo:. \
  "${schema}"
