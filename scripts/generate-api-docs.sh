#!/bin/bash

set -e

script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
gef_root=$(dirname "$script_dir")
output_path="${gef_root}/docs/api/"
src_base_url="https://github.com/hugsy/gef/blob/dev/"


check()
{
    python -c "import lazydocs" || exit 1
}


clean_doc()
{
    rm -fr -- ${output_path}/*.md
}


generate_doc()
{
    gdb -q \
        -ex "pi from lazydocs.generation import generate_docs" \
        -ex "pi generate_docs(paths=['__main__',], output_path='${output_path}')" \
        -ex quit
}

fixup_doc()
{
    mv ${output_path}/__main__.md ${output_path}/gef.md
    sed -i 's?# <kbd>module</kbd> `__main__`?# <kbd>module</kbd> `GEF`?' ${output_path}/gef.md
    sed -i 's?<a href="../../~/code/gef/gef.py">?<a href="https://github.com/hugsy/gef/blob/master/gef.py">?g' ${output_path}/gef.md

    # for item in ${output_path}/__main__.*.md; do
    #     mv ${item} ${item/__main__./gef.}
    # done
}

check
clean_doc
generate_doc ${api}
fixup_doc
