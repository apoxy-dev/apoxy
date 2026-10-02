#!/bin/bash
# Sends one line about a failed VPC gate job to SLACK_PERF_WEBHOOK_URL.
# Usage: perf-vpc-slack.sh RESULT_DIR (the PerfVPC output).
set -euo pipefail
dir=$1
run="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
at="apoxy@${GITHUB_SHA::7}"
code=$(cat "$dir/gate-exit" 2> /dev/null || echo none)
shopt -s nullglob
results=("$dir"/results/gate/*.json)
res=${results[0]:-}
if [ -z "$res" ]; then
  text="VPC perf gate ERROR on $at: no gate result."
elif [ "$code" = 0 ]; then
  text="VPC perf gate ERROR on $at: the gate passed, but a later step failed."
elif [ "$code" = 3 ]; then
  text="VPC perf gate INFRA on $at: $(jq -r '.infra_error' "$res")."
else
  text="VPC perf gate FAIL on $at: $(jq -r '"median \(.throughput.gbps) Gbps, runs \([.runs[].throughput.gbps | tostring] | join(" "))\(if .retried then ", retried" else "" end)"' "$res")"
  # A check line is "  METRIC GOT baseline BASE CHANGE REGRESSION".
  checks=$(awk '$NF == "REGRESSION" { printf "%s%s %s (baseline %s, %s)", sep, $1, $2, $4, $5; sep = "; " }' "$dir/compare-gate.txt" 2> /dev/null || true)
  if [ -n "$checks" ]; then
    text="$text; $checks"
  fi
  text="$text."
fi
jq -n --arg text "$text <$run|Run>" '{text: $text}' |
  curl -fsS --retry 3 -X POST -H 'Content-Type: application/json' --data @- "$SLACK_PERF_WEBHOOK_URL"
