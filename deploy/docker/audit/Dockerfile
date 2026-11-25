# Stage 1: Build Environment
FROM debian:trixie AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    cmake \
    ninja-build \
    pkg-config \
    git \
    ca-certificates \
    libssl-dev \
    libprotobuf-dev \
    protobuf-compiler \
    libgrpc++-dev \
    protobuf-compiler-grpc \
    libpqxx-dev \
    nlohmann-json3-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY . .

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DSECURECLOUD_BUILD_CLIENT=OFF

RUN cmake --build build --target securecloud-audit -j2

# Stage 2: Minimal Runtime Environment
FROM debian:trixie-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 \
    libgrpc++1.51t64 \
    libprotobuf32t64 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 securecloud \
 && useradd -u 10001 -g 10001 -s /sbin/nologin -M securecloud

COPY --from=builder --chown=securecloud:securecloud /workspace/build/src/audit/securecloud-audit /usr/local/bin/securecloud-audit

RUN chmod 0555 /usr/local/bin/securecloud-audit

WORKDIR /home/securecloud

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/securecloud-audit"]
