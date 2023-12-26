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
	echo "Please install cURL or wget and run again"
	exit 1
fi

# Backup gdbinit if any
if [ -f "${HOME}/.gdbinit" ]; then
    mv "${HOME}/.gdbinit" "${HOME}/.gdbinit.old"
fi

if [ $wget_found -eq 1 ]; then
    latest_tag=$(wget -q -O- "https://api.github.com/repos/hugsy/gef/tags" | grep "name" | head -1 | sed -e 's/"name": "\([^"]*\)",/\1/' -e 's/ *//')

    # Get the hash of the commit
    branch="${latest_tag}"
    ref=$(wget -q -O- https://api.github.com/repos/hugsy/gef/git/ref/heads/${branch} | grep '"sha"' | tr -s ' ' | cut -d ' ' -f 3 | tr -d "," | tr -d '"')

    # Download the file
    wget -q "https://github.com/hugsy/gef/raw/${branch}/gef.py" -O "${HOME}/.gef-${ref}.py"
elif [ $curl_found -eq 1 ]; then
    latest_tag=$(curl -s "https://api.github.com/repos/hugsy/gef/tags" | grep "name" | head -1 | sed -e 's/"name": "\([^"]*\)",/\1/' -e 's/ *//')

    # Get the hash of the commit
    branch="${latest_tag}"
    ref=$(curl --silent https://api.github.com/repos/hugsy/gef/git/ref/heads/${branch} | grep '"sha"' | tr -s ' ' | cut -d ' ' -f 3 | tr -d "," | tr -d '"')

    # Download the file
    curl --silent --location --output "${HOME}/.gef-${ref}.py" "https://github.com/hugsy/gef/raw/${branch}/gef.py"
fi

# Create the new gdbinit
echo "source ~/.gef-${ref}.py" > ~/.gdbinit

exit 0
