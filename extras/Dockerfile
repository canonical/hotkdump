FROM ubuntu:jammy

ARG DEBIAN_FRONTEND=noninteractive
RUN apt -y update && \
    apt -y install --no-install-recommends build-essential wget libcurses-ocaml-dev zlib1g-dev bison texinfo python3 ubuntu-dev-tools && \
    cd /tmp && \
    wget https://github.com/crash-utility/crash/archive/refs/tags/8.0.5.tar.gz && \
    tar -xvzf 8.0.5.tar.gz && \
    cd crash-8.0.5 && \
    make -j$(nproc) && \
    make install && \
    crash --version && \
    rm -rf /tmp/crash-8.0.5
COPY hotkdump /opt/hotkdump
RUN chmod +x /opt/hotkdump/main.py && \
    ln -sf /opt/hotkdump/main.py /usr/bin/hotkdump && \
    ls -lrah /usr/bin/hotkdump

