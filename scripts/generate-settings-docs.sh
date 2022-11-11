#!/usr/bin/env bash

set -e

SETTINGS_FILE="$(mktemp)"
GEF_DIR="$(pwd)"
GEF_MKDOC_YML="${GEF_DIR}/mkdocs.yml"
GEF_DOCS_DIR="${GEF_DIR}/docs/settings"

rm -fr -- "${GEF_DOCS_DIR}"
mkdir -- "${GEF_DOCS_DIR}"
rm -f -- ~/.gef.rc

echo "[+] Collect available settings"
gdb -q -ex 'gef config gef.disable_color 1' -ex 'gef config' -ex quit | awk '{print $1}' | sed '1,3d' > ${SETTINGS_FILE}

echo "[+] Add the reference to mkdocs"
echo "- Settings:" >> ${GEF_MKDOC_YML}

echo "[+] Create documentation for settings"
while read setting_long
do
    command=$(echo ${setting_long} | cut -d . -f1)
    fname="${GEF_DOCS_DIR}/${command}.md"
    if [ ! -f ${fname} ]; then
        echo "# Settings for command \`${command}\`\n\n" > $fname
        echo "  - ${command}: settings/${command}.md" >> ${GEF_MKDOC_YML}
    fi
done < ${SETTINGS_FILE}

gdb -q \
    -ex "gef config gef.disable_color 1" \
    -ex "pi for k,v in gef.config.items(): open(f'${GEF_DOCS_DIR}/{k.split(\".\",1)[0]}.md', 'a+').write(f'''
## Setting \`{k}\`\n\n
Type: \`{v.type.__name__}\`\n
Default: \`{v.value}\`\n
Description:\n> {v.description}\n
''')" \
    -ex quit > /dev/null
