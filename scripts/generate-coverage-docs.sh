#!/usr/bin/env bash

set -e

NB_CORES="$(grep --count '^processor' /proc/cpuinfo)"
TMPDIR_RUN="$(mktemp -d)"
TMPDIR_COV="$(mktemp)"
GEF_DIR="$(pwd)"
GEF_TESTS_DIR="${GEF_DIR}/tests"
GEF_DOCS_DIR="${GEF_DIR}/docs/coverage"
PY_VER=$(gdb -q -nx -ex 'pi print(f"{sys.version_info.major}.{sys.version_info.minor}", end="")' -ex quit)

rm -f -- "${GEF_DOCS_DIR}"/*

echo "[+] Generating coverage report in '${TMPDIR_RUN}'"
COVERAGE_DIR="${TMPDIR_RUN}" python${PY_VER} -m pytest -n ${NB_CORES} "${GEF_TESTS_DIR}"

echo "[+] Combining data to '${TMPDIR_COV}'"
python${PY_VER} -m coverage combine --data-file=${TMPDIR_COV} "${TMPDIR_RUN}"/*

echo "[+] Generating reports to '${GEF_DOCS_DIR}'"
python${PY_VER} -m coverage html --data-file="${TMPDIR_COV}" --include='*/gef.py' --directory="${GEF_DOCS_DIR}" --precision=4
python${PY_VER} -m coverage xml  --data-file="${TMPDIR_COV}" --include='*/gef.py' -o "${GEF_DOCS_DIR}/coverage.xml"
python${PY_VER} -m coverage json  --data-file="${TMPDIR_COV}" --include='*/gef.py' -o "${GEF_DOCS_DIR}/coverage.json"
