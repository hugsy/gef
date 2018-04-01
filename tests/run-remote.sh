#!/bin/bash
#
# Bash script to automate running the tests running from any remote machine 
# (assumes GDB+Python3, requires sudo NOPASSWD)
#
# On the host, run:
# $ sh -c "$(curl https://raw.githubusercontent.com/hugsy/gef/master/tests/run-remote.sh)"
#

set -e

pushd .
rm -fr /tmp/gef-tests
cd /tmp/gef-tests
sudo apt update
sudo apt upgrade -y
sudo apt install gdb git cmake gcc g++ pkg-config libglib2.0-dev python3-pip python3-setuptools python3-dev python3 make -y
sudo rm -fr -- /tmp/{keystone,capstone,unicorn}
sh -c "$(curl https://raw.githubusercontent.com/hugsy/stuff/master/update-trinity.sh)"
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib
pip3 install -U ropper cryptography
git clone https://github.com/hugsy/gef.git
cd gef
tests/test-runner.py

popd 
