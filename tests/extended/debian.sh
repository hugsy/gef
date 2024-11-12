#!/bin/bash
set -e
# set -x
# docker run -v /path/to/gef:/gef debian:bookworm "bash /gef/tests/extended/debian.sh"
apt update -qq
apt install -qq -y gdb-multiarch cmake gcc-multilib python3 python3-pip procps file elfutils binutils cmake gcc g++ gdbserver qemu-user locales
rm -rf /var/lib/apt/lists/* && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
export LANG=en_US.utf8
export LC_ALL=en_US.utf8

cd /gef
export PY_VER=`gdb-multiarch -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit`
echo Using Python ${PY_VER}
python${PY_VER} -m pip install --user --upgrade -r tests/requirements.txt -r docs/requirements.txt --break-system-packages
make -C tests/binaries
python${PY_VER} -m pytest -v -m "not benchmark" tests/
