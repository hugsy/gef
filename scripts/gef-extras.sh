#!/usr/bin/env bash

set -e

if [ $# -ge 1 ]; then
  DIR="$(realpath "$1")/gef-extras"
  test -d "${DIR}" || exit 1
elif [ -d "${HOME}/.config" ]; then
  DIR="${HOME}/.config/gef-extras"
else
  DIR="${HOME}/.gef-extras"
fi

git clone https://github.com/hugsy/gef-extras.git "${DIR}"
gdb -q -ex "gef config gef.extra_plugins_dir '${DIR}/scripts'" \
       -ex "gef config pcustom.struct_path '${DIR}/structs'" \
       -ex "gef config syscall-args.path '${DIR}/syscall-tables'" \
       -ex "gef config context.libc_args True" \
       -ex "gef config context.libc_args_path '${DIR}/glibc-function-args'" \
       -ex 'gef save' \
       -ex quit

exit 0
