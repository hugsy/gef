#!/bin/bash

set -e

version="$(date +%Y.%m)"
codename="$(random-word)"

echo "Push new release: ${version} - '${codename}' [y/N]: "
read res
if [ "${res}" == "y" ] || [ "${res}" == "Y" ]; then
    git tag --annotate "${version}" --message "Release: ${codename}" --sign
    git push origin "${version}"
fi
