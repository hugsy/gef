#!/usr/bin/env bash

set -e

# check dependencies
if [ ! "$(command -v python3)" ]; then
	echo "GEF requires Python3 installed."
	exit 1
fi

gdb_init="${HOME}/.gdbinit"
xdg_init="${HOME}/.config/gdb/gdbinit"

# Decide which gdbinit file to use
if [ -f "${xdg_init}" ]; then
    target_init="${xdg_init}"
else
    target_init="${gdb_init}"
fi

# Backup gdbinit if any
if [ -f "${target_init}" ] && [ -s "${target_init}" ]; then
    timestamp=$(date +%Y%m%d_%H%M%S)
    backup_file="${target_init}_${timestamp}.old"
    cp "${target_init}" "${backup_file}"
    echo "[*] Existing gdbinit saved as ${backup_file}"
else
    touch "${target_init}"
fi

tag=$(python3 -X utf8 -c 'import urllib.request as r,json as j; x=j.loads(r.urlopen("https://api.github.com/repos/hugsy/gef/tags").read()); print(x[0]["name"])')
python3 -X utf8 -c "import urllib.request as r; x=r.urlopen('https://github.com/hugsy/gef/raw/${tag}/gef.py').read(); print(x.decode('utf-8'))" > ${HOME}/.gef-${tag}.py

if [ -f "${HOME}/.gef-${tag}.py" ]; then
    # Update or insert GEF source line
    if grep -q "source ~/.gef-" "${target_init}"; then
        sed -i "s#source ~/.gef-.*\.py#source ~/.gef-${tag}.py#" "${target_init}"
        echo "[+] Updated GEF version in ${target_init}"
    else
        if [ ! -s "${target_init}" ]; then
            echo "source ~/.gef-${tag}.py" > "${target_init}"
        else
            sed -i "1i source ~/.gef-${tag}.py" "${target_init}"
        fi
        echo "[+] Added GEF source to ${target_init}"
    fi
    exit 0
else
    echo "GEF was not properly downloaded"
    exit 2
fi
