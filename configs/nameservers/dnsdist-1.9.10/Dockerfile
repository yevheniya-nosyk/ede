# Stage 1: Build
FROM ubuntu:22.04 AS builder

ARG SOFTWARE_VERSION=1.9.10
ENV DEBIAN_FRONTEND=noninteractive

# Install all the required packages to build
RUN apt-get update && apt-get install -y \
    wget libboost-dev libboost-filesystem-dev libboost-serialization-dev \
    libboost-system-dev libboost-thread-dev libboost-context-dev \
    libboost-test-dev libedit-dev g++ make pkg-config \
    libluajit-5.1-dev && \
    rm -rf /var/lib/apt/lists/*

# Download the source code and build
WORKDIR /build
RUN wget https://downloads.powerdns.com/releases/dnsdist-${SOFTWARE_VERSION}.tar.bz2 && \
    tar -xf dnsdist-${SOFTWARE_VERSION}.tar.bz2 && \
    cd dnsdist-${SOFTWARE_VERSION} && \
    ./configure && make && make install

# Stage 2: Run
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Only install runtime dependencies
RUN apt-get update && apt-get install -y \
    libboost-filesystem1.74.0  libboost-serialization1.74.0 \
    libboost-system1.74.0 libboost-thread1.74.0  \
    libboost-context1.74.0 libluajit-5.1-2 libedit2 && \
    rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /usr/local /usr/local

# Expose ports
EXPOSE 53/udp 53/tcp

# Create the empty configuration file at the default location
RUN touch /usr/local/etc/dnsdist.conf
