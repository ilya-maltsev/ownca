#!/bin/sh
# Build the OwnCA dev stack, optionally baking in CryptoPro CSP.
#
# CryptoPro is included ONLY if its .deb distribution is available on the host.
# This script stages that distribution into the Docker build context
# (dev_env/dashboard/vendor/cryptopro.tgz) so the Dockerfile can COPY it; the
# Dockerfile installs CryptoPro only when that file is present and otherwise
# builds a plain openssl+gost-engine image.
#
# Usage:
#   dev_env/build.sh                 # picks up dev_env/cryptopro_linux-amd64_deb.tgz if present
#   OWNCA_CRYPTOPRO_DIST=/path/to/cryptopro.tgz dev_env/build.sh
#   OWNCA_CRYPTOPRO_DIST=none dev_env/build.sh   # force a build WITHOUT CryptoPro
#
# After building, start as usual:  cd dev_env && docker compose up -d
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
VENDOR="$SCRIPT_DIR/dashboard/vendor"
STAGED="$VENDOR/cryptopro.tgz"

# Default distribution location: next to this script (git-ignored there).
# Override with OWNCA_CRYPTOPRO_DIST for a distribution elsewhere on the host.
DIST="${OWNCA_CRYPTOPRO_DIST:-$SCRIPT_DIR/cryptopro_linux-amd64_deb.tgz}"

mkdir -p "$VENDOR"
# Always start clean so a previous staged copy never leaks into a "no-CryptoPro"
# build.
rm -f "$STAGED"

if [ "$DIST" = "none" ]; then
    echo "[build] CryptoPro explicitly disabled (OWNCA_CRYPTOPRO_DIST=none)."
elif [ -f "$DIST" ]; then
    echo "[build] Staging CryptoPro distribution: $DIST"
    cp "$DIST" "$STAGED"
else
    echo "[build] No CryptoPro distribution at '$DIST' — building WITHOUT CryptoPro."
    echo "[build] (set OWNCA_CRYPTOPRO_DIST to a .tgz to include it)"
fi

cd "$SCRIPT_DIR"
docker compose build "$@"

# Don't leave the 37MB blob in the context after the build.
rm -f "$STAGED"
echo "[build] Done. Start with: cd dev_env && docker compose up -d"
