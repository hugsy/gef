FROM circleci/python:3.4

ENV PYTHONPATH /usr/local/lib/python3.4/site-packages

# Setup Python2 Dependencies
RUN sudo apt-get install python2.7 python-setuptools python-dev build-essential
RUN sudo python2 -m easy_install pip
RUN sudo python2 -m pip install pylint

# Setup Development Tools
RUN sudo apt-get update -y
RUN sudo apt-get install gdb git cmake gcc g++ pkg-config libglib2.0-dev -y

# Setup Python3 Dependencies
RUN sudo pip3 install keystone-engine capstone unicorn
RUN sudo pip3 install pylint ropper
RUN https://raw.githubusercontent.com/hugsy/stuff/master/update-trinity.sh | bash
