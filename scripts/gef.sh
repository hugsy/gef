#!/bin/bash

set -e

branch="master"
test "$1" == "dev" && branch="dev"

# Backup gdbinit if any
test -f "${HOME}/.gdbinit" && mv "${HOME}/.gdbinit" "${HOME}/.gdbinit.old"

# Get the hash of the commit
ref=$(curl --silent https://api.github.com/repos/hugsy/gef/git/ref/heads/${branch} | grep '"sha"' | tr -s ' ' | cut -d ' ' -f 3 | tr -d "," | tr -d '"')

# Download the file
curl --silent --location --output "${HOME}/.gef-${ref}.py" "https://github.com/hugsy/gef/raw/${branch}/gef.py"

# Create the new gdbinit
echo "source ~/.gef-${ref}.py" > ~/.gdbinit

exit 0
