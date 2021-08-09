#!/bin/bash

set -e

branch="master"

if [ "$1" = "dev" ]; then
    branch="dev"
    echo "set branch to dev"
fi

# Backup gdbinit if any
if [ -f "${HOME}/.gdbinit" ]; then
    mv "${HOME}/.gdbinit" "${HOME}/.gdbinit.old"
fi

# Get the hash of the commit
ref=$(wget -q -O- https://api.github.com/repos/hugsy/gef/git/ref/heads/${branch} | grep '"sha"' | tr -s ' ' | cut -d ' ' -f 3 | tr -d "," | tr -d '"')

# Download the file
wget -q "https://github.com/hugsy/gef/raw/${branch}/gef.py" -O "${HOME}/.gef-${ref}.py"
# Create the new gdbinit
echo "source ~/.gef-${ref}.py" > ~/.gdbinit

exit 0
