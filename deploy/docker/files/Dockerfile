# Stage 1: Build Environment
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    cmake \
    ninja-build \
    pkg-config \
    libprotobuf-dev \
    protobuf-compiler \
    libgrpc++-dev \
    protobuf-compiler-grpc \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY . .

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF

RUN cmake --build build --target securecloud-files

# Stage 2: Minimal Runtime Environment
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libprotobuf-dev \
    libgrpc++-dev \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 securecloud \
 && useradd -u 10001 -g 10001 -s /sbin/nologin -M securecloud

COPY --from=builder --chown=securecloud:securecloud /workspace/build/src/files/securecloud-files /usr/local/bin/securecloud-files

RUN chmod 0555 /usr/local/bin/securecloud-files

WORKDIR /home/securecloud

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/securecloud-files"]
