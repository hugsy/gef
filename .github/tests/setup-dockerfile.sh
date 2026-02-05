#!/bin/sh

[ -z "${1}" ] && echo "Provide a container image as an argument to this script" && exit 1

echo "FROM ${1}" > Dockerfile

cat >> Dockerfile << 'EOF'

# Install dependencies for Ubuntu-based images
RUN if [ -f /etc/debian_version ]; then \
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=n && \
  apt-get update && \
  apt-get install -y gdb-multiarch python3-dev python3-pip python3-wheel python3-setuptools \
    git cmake gcc g++ pkg-config libglib2.0-dev gdbserver qemu-user file; \
fi

# Install python3-full for Ubuntu 24.04
RUN if grep -q "24.04" /etc/os-release 2>/dev/null; then \
  apt-get install -y python3-full; \
fi

# Install dependencies for Fedora-based images
RUN if [ -f /etc/fedora-release ]; then \
  dnf install -y gdb gdb-gdbserver python3-devel python3-pip python3-wheel python3-setuptools python3-rpm \
    git cmake gcc gcc-c++ pkg-config glib2-devel qemu-user qemu-user-static file procps-ng && \
  dnf --enablerepo='*debug*' install -y glibc-debuginfo && \
  dnf clean all; \
fi

# Copy only requirements.txt for caching
COPY tests/requirements.txt /tmp/requirements.txt

# Install Python requirements
RUN PY_VER=$(gdb -q -nx -ex "pi print('.'.join(map(str, sys.version_info[:2])))" -ex quit 2>/dev/null || echo "3") && \
  if grep -q "24.04" /etc/os-release 2>/dev/null; then \
    python${PY_VER} -m pip install --break-system-packages --upgrade -r /tmp/requirements.txt; \
  else \
    python${PY_VER} -m pip install --upgrade -r /tmp/requirements.txt; \
  fi

RUN git config --global --add safe.directory /gef

WORKDIR /gef

# Copy entrypoint script
COPY .github/tests/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

EOF
