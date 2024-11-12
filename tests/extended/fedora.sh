#!/bin/bash
set -e
# set -x
# docker run -v /path/to/gef:/gef fedora:41 "bash /gef/tests/extended/fedora.sh"
dnf install -y gdb cmake gcc python3 python3-pip procps file elfutils binutils cmake gcc g++ gdbserver qemu-user
export LANG=en_US.utf8
export LC_ALL=en_US.utf8

cd /gef
alias gdb-multiarch=gdb
export PY_VER=`gdb-multiarch -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit`
echo Using Python ${PY_VER}
python${PY_VER} -m pip install --user --upgrade -r tests/requirements.txt -r docs/requirements.txt --break-system-packages
make -C tests/binaries
python${PY_VER} -m pytest -v -m "not benchmark" tests/
