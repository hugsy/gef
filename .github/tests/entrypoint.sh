#!/bin/sh

set -x

PY_VER=$(gdb -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit 2>/dev/null || echo "3")
GEF_CI_NB_CPU=$(grep -c ^processor /proc/cpuinfo)

# Setup GEF
echo "source /gef/gef.py" > /root/.gdbinit

# Verify GEF setup
gdb -q -ex "gef missing" -ex "gef help" -ex "gef config" -ex start -ex continue -ex quit /bin/pwd

# Build test binaries
make -C tests/binaries -j ${GEF_CI_NB_CPU}

# Run pytest
python${PY_VER} -m pytest --forked -n ${GEF_CI_NB_CPU} -v -m "not benchmark" tests/
