#!/bin/bash

set -e

if [ $# -ge 1 ]; then
  DIR="$(realpath $1)"
  test -d ${DIR} || exit 1
else
  DIR=${HOME}
fi

git clone https://github.com/hugsy/gef-extras.git ${DIR}/gef-extras
gdb -q -ex "gef config gef.extra_plugins_dir '${DIR}/gef-extras/scripts'" \
       -ex "gef config pcustom.struct_path '${DIR}/gef-extras/structs'" \
       -ex "gef config syscall-args.path '${DIR}/gef-extras/syscall-tables'" \
       -ex 'gef save' \
       -ex quit

exit 0
