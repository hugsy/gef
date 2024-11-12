#!/bin/bash
set -e
# set -x
# docker run -v /path/to/gef:/gef fedora:41 "bash /gef/tests/extended/fedora.sh"
dnf install -y gdb cmake gcc python3 python3-pip procps file elfutils binutils cmake gcc g++ gdbserver qemu-user git
export LANG=en_US.UTF8
export LC_ALL=en_US.UTF8

bash /gef/tests/extended/run_pytest.sh