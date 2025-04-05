#!/usr/bin/env bash

set -e

# check dependencies
if [ ! "$(command -v python3)" ]; then
	echo "GEF requires Python3 installed."
	exit 1
fi

# Backup gdbinit if any
if [ -f "${HOME}/.gdbinit" ]; then
    cp "${HOME}/.gdbinit" "${HOME}/.gdbinit.old"
    echo "Existing gdbinit saved as ${HOME}/.gdbinit.old"
else
    touch "${HOME}/.gdbinit"
fi

tag=$(python3 -X utf8 -c 'import urllib.request as r,json as j; x=j.loads(r.urlopen("https://api.github.com/repos/hugsy/gef/tags").read()); print(x[0]["name"])')
python3 -X utf8 -c "import urllib.request as r; x=r.urlopen('https://github.com/hugsy/gef/raw/${tag}/gef.py').read(); print(x.decode('utf-8'))" > ${HOME}/.gef-${tag}.py

if [ -f "${HOME}/.gef-${tag}.py" ]; then
    # Check if GEF is already sourced in gdbinit
    if grep -q "source ~/.gef-" ${HOME}/.gdbinit; then
        # Update GEF version in gdbinit
        sed -i "s#source ~/.gef-.*\.py#source ~/.gef-${tag}.py#" ${HOME}/.gdbinit
    else
        # If gdbinit was just created (empty file)
        if [ ! -s "${HOME}/.gdbinit" ]; then
            echo "source ~/.gef-${tag}.py" > ${HOME}/.gdbinit
        else # Add GEF source at 1st line
            sed -i "1i source ~/.gef-${tag}.py" ${HOME}/.gdbinit
        fi
    fi
    exit 0
else
    echo "GEF was not properly downloaded"
    exit 2
fi
