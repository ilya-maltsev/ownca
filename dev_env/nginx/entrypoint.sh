#!/bin/bash
set -e

CERT_DIR="/etc/nginx/certs"
DAYS=${CERT_DAYS:-365}
EXTRA_SANS="${CERT_EXTRA_SANS:-}"

generate_gost_ca() {
    echo "[PKI] Generating GOST CA..."
    openssl req -x509 \
        -newkey gost2012_256 -pkeyopt paramset:A \
        -nodes -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
        -days ${DAYS} -subj "/C=RU/O=OwnCA Dev/CN=OwnCA GOST CA"
    chmod 600 "${CERT_DIR}/ca.key"
}

generate_rsa_ca() {
    echo "[PKI] Generating RSA CA..."
    openssl req -x509 -newkey rsa:2048 \
        -nodes -keyout "${CERT_DIR}/ca-rsa.key" -out "${CERT_DIR}/ca-rsa.crt" \
        -days ${DAYS} -subj "/C=RU/O=OwnCA Dev/CN=OwnCA RSA CA"
    chmod 600 "${CERT_DIR}/ca-rsa.key"
}

generate_cert() {
    local algo=$1  # gost or rsa
    local name=$2
    local cn=$3
    local san=$4
    local key="${CERT_DIR}/${name}.key"
    local csr="${CERT_DIR}/${name}.csr"
    local cert="${CERT_DIR}/${name}.crt"

    if [ "$algo" = "gost" ]; then
        local ca_cert="${CERT_DIR}/ca.crt"
        local ca_key="${CERT_DIR}/ca.key"
        echo "[PKI] GOST cert: ${cn} -> ${name}"
        openssl req -new \
            -newkey gost2012_256 -pkeyopt paramset:A \
            -nodes -keyout "${key}" -out "${csr}" \
            -subj "/C=RU/O=OwnCA Dev/CN=${cn}"
    else
        local ca_cert="${CERT_DIR}/ca-rsa.crt"
        local ca_key="${CERT_DIR}/ca-rsa.key"
        echo "[PKI] RSA  cert: ${cn} -> ${name}"
        openssl req -new -newkey rsa:2048 \
            -nodes -keyout "${key}" -out "${csr}" \
            -subj "/C=RU/O=OwnCA Dev/CN=${cn}"
    fi

    local ext="${CERT_DIR}/${name}.ext"
    cat > "${ext}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${san}
EOF

    openssl x509 -req -in "${csr}" \
        -CA "${ca_cert}" -CAkey "${ca_key}" -CAcreateserial \
        -out "${cert}" -days ${DAYS} -extfile "${ext}"

    chmod 600 "${key}"
    rm -f "${csr}" "${ext}"
}

mkdir -p "${CERT_DIR}"

if [ ! -f "${CERT_DIR}/ca.crt" ]; then
    echo "[PKI] Generating full PKI..."

    # GOST CA + GOST server cert (frontend TLS)
    generate_gost_ca
    BASE_SAN="DNS:localhost,IP:127.0.0.1"
    if [ -n "${EXTRA_SANS}" ]; then
        BASE_SAN="${BASE_SAN},${EXTRA_SANS}"
    fi

    generate_cert gost "nginx" "ownca-nginx" "${BASE_SAN}"

    # RSA CA + RSA server cert (frontend TLS for standard browsers)
    generate_rsa_ca
    generate_cert rsa "nginx-rsa" "ownca-nginx-rsa" "${BASE_SAN}"

    echo "[PKI] Done."
    ls -la "${CERT_DIR}"
else
    echo "[PKI] CA found, skipping generation."
fi

echo "[NGINX] Starting nginx..."
exec nginx -g "daemon off;"
