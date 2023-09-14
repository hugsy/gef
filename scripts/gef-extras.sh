#!/usr/bin/env bash
#
# Install gef-extras
# Requires git and pip already installed
#
set -e

usage() { echo "Usage: $0 [-b <OtherBranchName|tag>] [-p <path_to_install>]" 1>&2; exit 1; }

latest_tag=$(curl -s "https://api.github.com/repos/hugsy/gef/tags" | grep "name" | head -1 | sed -e 's/"name": "\([^"]*\)",/\1/' -e 's/ *//')

branch=${latest_tag}
while getopts ":b:p:" o; do
    case "${o}" in
        b)
            branch=${OPTARG}
            ;;
        p)
            path=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done

if [ -z "$path" ]; then
  if [ -d "${HOME}/.config" ]; then
    DIR="${HOME}/.config/gef-extras"
  else
    DIR="${HOME}/.gef-extras"
  fi
else
  DIR="$(realpath "$path")/gef-extras"
  test -d "${DIR}" || exit 1
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
