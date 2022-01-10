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
    # rename
    mv ${output_path}/__main__.md ${output_path}/gef.md

    # replace the title
    sed -i 's?# <kbd>module</kbd> `__main__`?# <kbd>module</kbd> `GEF`?' ${output_path}/gef.md

    # fix the hrefs
    sed -i -ze 's!<a href="\([^"]*\)[^`]*`\([^`]*\)`!<a href="https://cs.github.com/hugsy/gef?q=\2"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>\n\n## <kbd>function</kbd> `\2`!g' ./docs/api/gef.md
}

check
clean_doc
generate_doc ${api}
fixup_doc
