FROM ubuntu:22.04

ENV PATH $PATH:/usr/local/go/bin

RUN apt update -y -q && \
    DEBIAN_FRONTEND=noninteractive apt install --no-install-recommends -y -q \
        curl \
        build-essential \
        ca-certificates \
        wget \
        gnupg2 \
        git \
        llvm \
        libbpf-dev \
        clang && \
    curl -s https://storage.googleapis.com/golang/go1.19.1.linux-amd64.tar.gz | tar -v -C /usr/local -xz

WORKDIR /go/src/qos