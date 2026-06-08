FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    afl++ \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    curl \
    gdb \
    git \
    lld \
    llvm \
    make \
    ninja-build \
    pkg-config \
    python3 \
    python3-venv \
    rsync \
    time \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
ENV PYTHONPATH=/work/src
