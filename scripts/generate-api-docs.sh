#!/usr/bin/env bash

set -e

script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
gef_root=$(dirname "$script_dir")
output_path="${gef_root}/docs/api/"
src_base_url="https://github.com/hugsy/gef/blob/dev/"
full_doc_path="${gef_root}/docs/api/gef.md"

check()
{
    python -c "import lazydocs" || exit 1
}


clean_doc()
{
    rm -fr -- "${output_path}/*.md"
}


generate_doc()
{
    api="$1"

    gdb -q \
        -ex "pi from lazydocs.generation import generate_docs" \
        -ex "pi generate_docs(paths=['${api}'], output_path='${output_path}')" \
        -ex quit
}

fixup_doc()
{
    # rename
    mv "${output_path}/__main__.md" "${full_doc_path}"

    # replace the title
    sed -i 's?# <kbd>module</kbd> `__main__`?# <kbd>module</kbd> `GEF`?' "${full_doc_path}"

    # fix the hrefs
    sed -i -ze 's!<a href="\([^"]*\)[^`]*`\([^`]*\)`!<a href="https://cs.github.com/hugsy/gef?q=\2"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>\n\n## <kbd>function</kbd> `\2`!g' "${full_doc_path}"
}

check
clean_doc
generate_doc "__main__"
fixup_doc
