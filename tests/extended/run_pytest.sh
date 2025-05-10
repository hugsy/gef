#!/bin/bash
set -e

git config --global --add safe.directory /gef
cd /gef
export PY_VER=`gdb-multiarch -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit`
echo Using Python ${PY_VER}
python${PY_VER} -m pip install --user --upgrade -r tests/requirements.txt -r docs/requirements.txt --break-system-packages
make -C tests/binaries -j4
python${PY_VER} -m pytest --forked -n 4 -v -m "not benchmark" tests/
