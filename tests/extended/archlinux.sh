

#!/bin/bash
set -e
# set -x
# docker run -v /path/to/gef:/gef archlinux:base-20241110.0.278197⁠ "bash /gef/tests/extended/archlinux.sh"
pacman -Suy
pacman -Suy --noconfirm gdb cmake gcc python3 procps file elfutils binutils cmake gcc qemu-user locales git python-pip make
export LANG=en_US.UTF8
export LC_ALL=en_US.UTF8

alias gdb-multiarch=gdb
bash /gef/tests/extended/run_pytest.sh
