# Stage 1: Build
FROM ubuntu:18.04 AS builder

ARG SOFTWARE_VERSION=9.12.4
ENV DEBIAN_FRONTEND=noninteractive

# Install all the required packages to build
RUN apt-get update && apt-get install -y \
    wget xz-utils build-essential libnghttp2-dev libcap-dev \
    libssl-dev perl pkg-config python3-pip && \
    pip3 install ply && \
    rm -rf /var/lib/apt/lists/*

# Download the source code and build
WORKDIR /build
RUN wget https://downloads.isc.org/isc/bind9/${SOFTWARE_VERSION}/bind-${SOFTWARE_VERSION}.tar.gz && \
    tar -xf bind-${SOFTWARE_VERSION}.tar.gz && \
    cd bind-${SOFTWARE_VERSION} && \
    # Ensure we can sign with a very high number of iterations
    sed -i "/else if (minbits <= 2048)/d" lib/dns/nsec3.c && \
    sed -i "/*iterationsp = 500;/d" lib/dns/nsec3.c && \
    ./configure && make && make install

# Stage 2: Run
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# Only install runtime dependencies
RUN apt-get update && apt-get install -y \
    libnghttp2-14 libcap2 libssl1.1 libuv1 && \
    rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /usr/local /usr/local
