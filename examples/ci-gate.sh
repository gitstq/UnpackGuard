#!/usr/bin/env bash
# CI 归档安全闸门示例 / example CI gate
# 用法 / usage: ./ci-gate.sh <archive> [fail-level]
#
# 退出码约定 / exit codes:
#   0 = 未命中阈值 / below threshold
#   2 = 命中阈值，
#   阻塞流水线 / above threshold, blocks the pipeline
#   3 = 归档无法解析 / 归档无法解析
# 用法/usage: ./ci-gate.sh <archive> [fail-level]

set -euo pipefail

ARCHIVE="${1:-}"
LEVEL="${2:-high}"

if [ -z "${ARCHIVE}" ]; then
  echo "usage: $0 <archive> [fail-level]" >&2
  exit 3
fi

echo "== 1/3 identify =="
unpackguard sniff "${ARCHIVE}" --no-color

echo "== 2/3 plan =="
unpackguard plan "${ARCHIVE}" --dest ./unpacked --no-color || true

echo "== 3/3 scan =="
if unpackguard scan "${ARCHIVE}" --fail-level "${LEVEL}" --sarif > unpackguard.sarif; then
  echo "✅ passed at level=${LEVEL}"
  exit 0
else
  code=$?
  echo "❌ blocked at level=${LEVEL}; see unpackguard.sarif"
  exit "${code}"
fi
