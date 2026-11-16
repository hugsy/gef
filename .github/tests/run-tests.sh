#!/bin/sh

[ -z "${1}" ] && echo "Provide a container tag as an argument to this script" && exit 1

docker run --privileged --rm -e GITHUB_ACTIONS -v "$PWD:/gef" gef-test:${1}
