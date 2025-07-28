# Stage 1: Build
FROM ubuntu:20.04 AS builder

ARG SOFTWARE_VERSION=9.18.26
ENV DEBIAN_FRONTEND=noninteractive

# Install all the required packages to build
RUN apt-get update && apt-get install -y \
    wget xz-utils build-essential libnghttp2-dev libcap-dev \
    libssl-dev libuv1-dev perl pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Download the source code and build
WORKDIR /build
RUN wget https://downloads.isc.org/isc/bind9/${SOFTWARE_VERSION}/bind-${SOFTWARE_VERSION}.tar.xz && \
    tar -xf bind-${SOFTWARE_VERSION}.tar.xz && \
    cd bind-${SOFTWARE_VERSION} && \
    ./configure && make && make install

# Stage 2: Run
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Only install runtime dependencies
RUN apt-get update && apt-get install -y \
    libnghttp2-14 libcap2 libssl1.1 libuv1 && \
    rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /usr/local /usr/local

# Avoid the "named: error while loading shared libraries: libisc" error when running named
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/bind9.conf && ldconfig

# Create the empty configuration file at the default location
RUN touch /usr/local/etc/named.conf
