#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"

# Configurable variables
CODEGEN_VERSION=v0.30.1 # Should match the k8s.io/apimachinery version in go.mod
BOILERPLATE_FILE="${ROOT_DIR}/codegen/boilerplate.go.txt"

echo "Generating deepcopy helpers..."

go run "k8s.io/code-generator/cmd/deepcopy-gen@${CODEGEN_VERSION}" \
  --output-file zz_generated.deepcopy.go \
  --go-header-file "${BOILERPLATE_FILE}" \
  ./api/config/v1alpha1 \
  ./api/controllers/v1alpha1 \
  ./api/core/v1alpha \
  ./api/extensions/v1alpha1 \
  ./api/extensions/v1alpha2 \
  ./api/gateway/v1 \
  ./pkg/gateway/gatewayapi \
  ./pkg/gateway/ir

echo "Generating register helpers..."

go run "k8s.io/code-generator/cmd/register-gen@${CODEGEN_VERSION}" \
  --output-file zz_generated.register.go \
  --go-header-file "${BOILERPLATE_FILE}" \
  ./api/config/v1alpha1 \
  ./api/controllers/v1alpha1 \
  ./api/core/v1alpha \
  ./api/extensions/v1alpha1 \
  ./api/extensions/v1alpha2 \
  ./api/gateway/v1 \
  ./pkg/gateway/gatewayapi \
  ./pkg/gateway/ir

echo "Generating client code..."

go run "k8s.io/code-generator/cmd/client-gen@${CODEGEN_VERSION}" \
  --go-header-file "${BOILERPLATE_FILE}" \
  --output-dir "client/" \
  --output-pkg "github.com/apoxy-dev/apoxy/client" \
  --input-base "github.com/apoxy-dev/apoxy" \
  --clientset-name "versioned" \
  --input "./api/controllers/v1alpha1" \
  --input "./api/core/v1alpha" \
  --input "./api/extensions/v1alpha1" \
  --input "./api/extensions/v1alpha2" \
  --input "./api/gateway/v1" \
  --input "./api/policy/v1alpha1"

echo "Generating listers and informers..."

go run "k8s.io/code-generator/cmd/lister-gen@${CODEGEN_VERSION}" \
  --go-header-file "${BOILERPLATE_FILE}" \
  --output-dir "client/listers" \
  --output-pkg "github.com/apoxy-dev/apoxy/client" \
  ./api/controllers/v1alpha1 \
  ./api/core/v1alpha \
  ./api/extensions/v1alpha1 \
  ./api/extensions/v1alpha2 \
  ./api/gateway/v1 \
  ./api/policy/v1alpha1

go run "k8s.io/code-generator/cmd/informer-gen@${CODEGEN_VERSION}" \
  --go-header-file "${BOILERPLATE_FILE}" \
  --output-dir "client/informers" \
  --output-pkg "github.com/apoxy-dev/apoxy/client/informers" \
  --versioned-clientset-package "github.com/apoxy-dev/apoxy/client/versioned" \
  --listers-package=github.com/apoxy-dev/apoxy/client/listers \
  --single-directory \
  ./api/controllers/v1alpha1 \
  ./api/core/v1alpha \
  ./api/extensions/v1alpha1 \
  ./api/extensions/v1alpha2 \
  ./api/gateway/v1 \
  ./api/policy/v1alpha1

echo "Generating OpenAPI schema..."

# Sadly no published tags.
go run "k8s.io/kube-openapi/cmd/openapi-gen@master" \
  --go-header-file "${BOILERPLATE_FILE}" \
  --output-dir "api/generated" \
  --output-pkg "generated" \
  --output-file zz_generated.openapi.go \
  --report-filename /dev/null \
  k8s.io/api/core/v1 \
  k8s.io/apimachinery/pkg/api/resource \
  k8s.io/apimachinery/pkg/apis/meta/v1 \
  k8s.io/apimachinery/pkg/runtime \
  k8s.io/apimachinery/pkg/util/intstr \
  k8s.io/apimachinery/pkg/version \
  sigs.k8s.io/gateway-api/apis/v1 \
  ./api/controllers/v1alpha1 \
  ./api/core/v1alpha \
  ./api/extensions/v1alpha1 \
  ./api/extensions/v1alpha2 \
  ./api/gateway/v1 \
  ./api/policy/v1alpha1
