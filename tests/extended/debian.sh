#!/bin/bash
set -e
# set -x
# docker run -v /path/to/gef:/gef debian:bookworm "bash /gef/tests/extended/debian.sh"
apt update -qq
apt install -qq -y gdb-multiarch cmake gcc-multilib python3 python3-pip procps file elfutils binutils cmake gcc g++ gdbserver qemu-user locales git
rm -rf /var/lib/apt/lists/* && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
export LANG=en_US.UTF8
export LC_ALL=en_US.UTF8

bash /gef/tests/extended/run_pytest.sh