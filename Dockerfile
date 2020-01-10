FROM circleci/python:3.4

ENV PYTHONPATH /usr/local/lib/python3.4/site-packages

# Setup Development Tools
RUN sudo apt-get update -y
RUN sudo apt-get install gdb git cmake gcc g++ pkg-config libglib2.0-dev -y

# Setup Python3 Dependencies
COPY requirements.txt /home/circleci/requirements.txt
RUN sudo pip3 install -r ~/requirements.txt
RUN curl https://raw.githubusercontent.com/hugsy/stuff/master/update-trinity.sh | bash
