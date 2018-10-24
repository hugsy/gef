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
RUN curl https://gist.githubusercontent.com/Grazfather/91e1ea3c3b51be844552263ce0f0d538/raw/76ff432159654e83db7159df7027ca4b11a2bdd4/install-trinity.sh | bash
