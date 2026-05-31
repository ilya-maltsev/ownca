# Stage 1: Build gost-engine from source
FROM debian:bookworm AS gost-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ gcc make pkg-config git cmake libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Upstream gost-engine, latest tag — nginx only uses the engine for TLS
# termination (gost ciphers) and doesn't care about the dashboard's
# PKCS#12 patches. Keeping nginx on the upstream engine + system OpenSSL
# 3.0 avoids a compiler/ABI shuffle for a feature it doesn't use.
RUN git clone https://github.com/gost-engine/engine.git gost-engine && \
    cd gost-engine && \
    LATEST_TAG=$(git tag --sort=-v:refname | head -1) && \
    git checkout ${LATEST_TAG} && \
    git submodule update --init

RUN cd gost-engine && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr && \
    cmake --build . --config Release -j$(nproc) && \
    cmake --build . --target install --config Release

RUN openssl engine gost -c

# Stage 2: Nginx with GOST support
FROM nginx:stable-bookworm

COPY --from=gost-builder /usr/lib/x86_64-linux-gnu/engines-3/gost.so /usr/lib/x86_64-linux-gnu/engines-3/gost.so
COPY --from=gost-builder /usr/bin/gostsum /usr/bin/gostsum
COPY --from=gost-builder /usr/bin/gost12sum /usr/bin/gost12sum

# Replace OpenSSL config with clean GOST-enabled version
COPY openssl-gost.cnf /etc/ssl/openssl.cnf

# Verify GOST engine and algorithms
RUN openssl engine gost -c && \
    openssl req -x509 -newkey gost2012_256 -pkeyopt paramset:A \
      -nodes -keyout /tmp/test.key -out /tmp/test.crt -days 1 \
      -subj "/CN=build-test" && rm -f /tmp/test.*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY nginx.conf /etc/nginx/nginx.conf

ENTRYPOINT ["/entrypoint.sh"]
