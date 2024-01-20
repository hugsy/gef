#!/usr/bin/env bash

set -e

curl_found=0
wget_found=0

# check dependencies
if [ "$(command -v curl)" ]; then
	curl_found=1
elif [ "$(command -v wget)" ]; then
	wget_found=1
else
	echo "The installer requires cURL or wget installed."
	exit 1
fi

# Backup gdbinit if any
if [ -f "${HOME}/.gdbinit" ]; then
    mv "${HOME}/.gdbinit" "${HOME}/.gdbinit.old"
fi

if [ $wget_found -eq 1 ]; then
    # Get the tag of the latest stable
    tag=$(wget -q -O- "https://api.github.com/repos/hugsy/gef/tags" | grep "name" | head -1 | sed -e 's/"name": "\([^"]*\)",/\1/' -e 's/ *//')

    # Download the file
    wget -q "https://github.com/hugsy/gef/raw/${tag}/gef.py" -O "${HOME}/.gef-${tag}.py"
elif [ $curl_found -eq 1 ]; then
    # Get the tag of the latest stable
    tag=$(curl -s "https://api.github.com/repos/hugsy/gef/tags" | grep "name" | head -1 | sed -e 's/"name": "\([^"]*\)",/\1/' -e 's/ *//')

    # Download the file
    curl --silent --location --output "${HOME}/.gef-${tag}.py" "https://github.com/hugsy/gef/raw/${tag}/gef.py"
fi

if [ -f "${HOME}/.gef-${tag}.py}" ]; then
    # Create the new gdbinit
    echo "source ~/.gef-${tag}.py" > ~/.gdbinit
    exit 0
fi

echo "GEF was not properly downloaded"
exit 1

