# Stage 1: Build OpenSSL 3.5 + the patched gost-engine from source.
#
# The dashboard's TK-26 PKCS#12 export path relies on the RFC 9337 / RFC 9548
# PBE machinery now merged into upstream gost-engine (master, via PR #527), so
# stock `openssl pkcs12 -export -keypbe kuznyechik-ctr-acpkm
# -certpbe kuznyechik-ctr-acpkm -macalg md_gost12_512` produces real TK-26
# wire format. The engine's CMakeLists requires OpenSSL >= 3.4, but Debian
# bookworm ships 3.0.x — so we build OpenSSL 3.5 from source into a private
# prefix (/opt/openssl-3) and link the engine against that. Rpath baked into
# /opt/openssl-3/bin/openssl keeps Debian's libssl3 (used by Python's ssl
# module) and our 3.5 cleanly separated.
FROM python:3.10.12-bookworm AS gost-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ gcc make pkg-config git cmake curl ca-certificates perl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG OPENSSL_VERSION=3.5.0
RUN curl -fsSL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" -o openssl.tar.gz && \
    tar -xzf openssl.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \
    ./config --prefix=/opt/openssl-3 \
             --openssldir=/opt/openssl-3/ssl \
             --libdir=lib \
             shared \
             -Wl,-rpath,/opt/openssl-3/lib && \
    make -j$(nproc) && \
    make install_sw && \
    cd .. && rm -rf openssl-${OPENSSL_VERSION} openssl.tar.gz

# Tracks master tip — every `--no-cache` rebuild picks up upstream HEAD.
RUN git clone --branch master --depth 1 \
        https://github.com/gost-engine/engine.git gost-engine && \
    cd gost-engine && \
    git submodule update --init

RUN cd gost-engine && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release \
             -DCMAKE_INSTALL_PREFIX=/opt/openssl-3 \
             -DOPENSSL_ROOT_DIR=/opt/openssl-3 \
             -DOPENSSL_LIBRARIES=/opt/openssl-3/lib \
             -DOPENSSL_ENGINES_DIR=/opt/openssl-3/lib/engines-3 && \
    cmake --build . --config Release -j$(nproc) && \
    cmake --build . --target install --config Release

# Stage 2: Dashboard with GOST support
FROM python:3.10.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        gettext libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Bring our OpenSSL 3.5 + the patched gost.so into the runtime image. The
# rpath baked into /opt/openssl-3/bin/openssl ensures it always picks up
# /opt/openssl-3/lib/libcrypto.so.3 — Debian's libssl3 stays for Python.
COPY --from=gost-builder /opt/openssl-3 /opt/openssl-3

# Symlink the engine into the path the existing openssl-gost.cnf expects
# (`/usr/lib/x86_64-linux-gnu/engines-3/gost.so`) so the cnf stays shared
# with the nginx image without forking.
RUN mkdir -p /usr/lib/x86_64-linux-gnu/engines-3 && \
    ln -sf /opt/openssl-3/lib/engines-3/gost.so \
           /usr/lib/x86_64-linux-gnu/engines-3/gost.so

# /opt/openssl-3/bin first on PATH → `subprocess.run(['openssl', ...])` from
# the Django views hits the patched 3.5 binary; the rest of the system can
# still find `/usr/bin/openssl` through PATH lookup if anything needs it.
ENV PATH="/opt/openssl-3/bin:${PATH}"

COPY dev_env/nginx/openssl-gost.cnf /etc/ssl/openssl.cnf

ENV OPENSSL_CONF="/etc/ssl/openssl.cnf"

WORKDIR /opt/app

COPY ownca_dashboard/requirements.txt /opt/app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ownca_dashboard /opt/app

COPY dev_env/dashboard/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8001

ENV BIND_ADDRESS="127.0.0.1:8001"
ENTRYPOINT ["/entrypoint.sh"]
