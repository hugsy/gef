#!/usr/bin/env bash
#
# Install gef-extras
# Requires git and pip already installed
#
set -e

branch="main"
if [ "$1" = "dev" ]; then
  branch="dev"
  echo "set branch to dev"
  if [ $# -ge 2 ]; then
    DIR_ARG=$2
  fi
else
  if [ $# -ge 1 ]; then
    DIR_ARG=$1
  fi
fi

if [ -z DIR_ARG ]; then
  DIR="$(realpath "$DIR_ARG")/gef-extras"
  test -d "${DIR}" || exit 1
elif [ -d "${HOME}/.config" ]; then
  DIR="${HOME}/.config/gef-extras"
else
  DIR="${HOME}/.gef-extras"
fi

git clone --branch ${branch} https://github.com/hugsy/gef-extras.git "${DIR}"
ver=$(gdb -q -nx -ex 'pi print(f"{sys.version_info.major}.{sys.version_info.minor}", end="")' -ex quit)
python${ver} -m pip install --requirement "${DIR}"/requirements.txt --upgrade
gdb -q -ex "gef config gef.extra_plugins_dir '${DIR}/scripts'" \
       -ex "gef config pcustom.struct_path '${DIR}/structs'" \
       -ex "gef config syscall-args.path '${DIR}/syscall-tables'" \
       -ex "gef config context.libc_args True" \
       -ex "gef config context.libc_args_path '${DIR}/glibc-function-args'" \
       -ex 'gef save' \
       -ex quit

exit 0
