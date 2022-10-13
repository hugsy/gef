#!/usr/bin/env bash

set -e
set -x

NB_CORES="$(grep --count '^processor' /proc/cpuinfo)"
TMPDIR_RUN="$(mktemp -d)"
TMPDIR_COV="$(mktemp)"
GEF_DIR="$(pwd)"
GEF_TESTS_DIR="${GEF_DIR}/tests"
GEF_DOCS_DIR="${GEF_DIR}/docs/coverage"

rm -f -- "${GEF_DOCS_DIR}"/*

echo "[+] Generating coverage report in '${TMPDIR_RUN}'"
COVERAGE_DIR="${TMPDIR_RUN}" python3.9 -m pytest -n ${NB_CORES} "${GEF_TESTS_DIR}"

echo "[+] Combining data to '${TMPDIR_COV}'"
python3.9 -m coverage combine --data-file=${TMPDIR_COV} "${TMPDIR_RUN}"/*

echo "[+] Generating HTML report to '${GEF_DOCS_DIR}'"
python3.9 -m coverage html --data-file="${TMPDIR_COV}" --include='*/gef.py' --directory="${GEF_DOCS_DIR}"
