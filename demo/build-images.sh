#!/bin/bash
#
# This file is a part of OwnCA,
# Certificate Authority GUI based on Django and OpenSSL 
#
# Copyright (C) 2026 Ilya Maltsev
# email: i.y.maltsev@yandex.ru
#
# OwnCA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OwnCA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OwnCA.  If not, see <http://www.gnu.org/licenses/>.
#
# Build, export and import Docker images for the OwnCA demo environment.
#
# Usage:
#   bash build-images.sh                       # build all images (default)
#   bash build-images.sh build                 # same as above
#   bash build-images.sh build dashboard       # build only selected images
#   bash build-images.sh export                # export all images + deploy files
#   bash build-images.sh export nginx          # export only selected images + deploy files
#   bash build-images.sh import                # load all images from archive
#   bash build-images.sh import dashboard      # load only selected images
#   bash build-images.sh all                   # build + export
#   bash build-images.sh all dashboard         # build + export selected
#
# Short names:
#   dashboard (dash), nginx, postgres (pg)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_NAME="$(basename "${SCRIPT_DIR}")"
ARCHIVE="${SCRIPT_DIR}/ownca-images.tar.gz"
DOCKER_IMAGES_TAR="docker-images.tar"

# Application images (locally built)
APP_IMAGES="ownca-nginx:latest ownca-dashboard:latest"
# Infrastructure images (pulled from registry)
INFRA_IMAGES="postgres:16"
# All images for export/import
ALL_IMAGES="${APP_IMAGES} ${INFRA_IMAGES}"

# --- Selection helpers --------------------------------------------------------

resolve_image() {
    case "$1" in
        dashboard|dash)  echo "ownca-dashboard:latest" ;;
        nginx)           echo "ownca-nginx:latest" ;;
        postgres|pg)     echo "postgres:16" ;;
        *) echo "" ;;
    esac
}

SELECTED=()

parse_selection() {
    for name in "$@"; do
        local full
        full=$(resolve_image "$name")
        if [ -z "$full" ]; then
            echo "ERROR: Unknown image name: $name"
            echo "Available: dashboard (dash), nginx, postgres (pg)"
            exit 1
        fi
        SELECTED+=("$full")
    done
}

# Return 0 if image is selected (or no selection = all).
is_selected() {
    local img="$1"
    [ ${#SELECTED[@]} -eq 0 ] && return 0
    for s in "${SELECTED[@]}"; do
        [ "$s" = "$img" ] && return 0
    done
    return 1
}

# Build space-separated list of selected images (for docker save/load).
selected_images_list() {
    if [ ${#SELECTED[@]} -eq 0 ]; then
        echo "${ALL_IMAGES}"
    else
        echo "${SELECTED[*]}"
    fi
}

show_help() {
    cat <<'EOF'
Usage: build-images.sh <command> [image ...]

Commands:
  build    Build Docker images (default if no command given)
  export   Save Docker images + deploy files to ownca-images.tar.gz
  import   Load Docker images from archive (extract archive first)
  all      Build + export
  help     Show this help

Image short names (optional — omit to operate on all):
  dashboard (dash)   ownca-dashboard:latest
  nginx              ownca-nginx:latest
  postgres  (pg)     postgres:16

Examples:
  bash build-images.sh                      # build all
  bash build-images.sh build dashboard      # build only dashboard
  bash build-images.sh export nginx         # export only nginx + deploy files
  bash build-images.sh all dashboard        # build + export dashboard only
EOF
}

# --- Core functions -----------------------------------------------------------

# Whitelist of files/dirs copied into each image's Docker build context.
# Anything outside these lists (docs, planning, .git, dev tooling, runtime
# data, etc.) stays out of the build context.
DASHBOARD_FILES=(
    ownca_dashboard/config
    ownca_dashboard/dashboard
    ownca_dashboard/locale
    ownca_dashboard/manage.py
    ownca_dashboard/requirements.txt
    ownca_dashboard/staticfiles
    dev_env/nginx/openssl-gost.cnf
    dev_env/dashboard/entrypoint.sh
)
NGINX_FILES=(Dockerfile entrypoint.sh nginx.conf openssl-gost.cnf)

_STAGED_DIRS=()
_cleanup_staged() {
    local d
    for d in "${_STAGED_DIRS[@]}"; do
        [ -d "${d}" ] && rm -rf "${d}"
    done
}
trap _cleanup_staged EXIT

# Stage a whitelist of files/dirs from ${src} into a fresh tmp dir, preserving
# nested paths so the staged context mirrors the source tree layout.
# Usage: ctx=$(stage_build_context <src_dir> <path1> <path2> ...)
stage_build_context() {
    local src="$1"; shift
    local dir
    dir="$(mktemp -d -t ownca-build-ctx.XXXXXX)"
    _STAGED_DIRS+=("${dir}")
    local item parent
    for item in "$@"; do
        if [ ! -e "${src}/${item}" ]; then
            echo "ERROR: required file '${item}' not found in ${src}" >&2
            exit 1
        fi
        parent="$(dirname "${item}")"
        if [ "${parent}" != "." ]; then
            mkdir -p "${dir}/${parent}"
        fi
        cp -a "${src}/${item}" "${dir}/${item}"
    done
    echo "${dir}"
}

pull_infra() {
    for img in ${INFRA_IMAGES}; do
        if is_selected "$img"; then
            echo ""
            echo "--- Pulling ${img} ---"
            docker pull "${img}"
        fi
    done
}

build_images() {
    pull_infra

    local ctx

    if is_selected "ownca-nginx:latest"; then
        echo ""
        echo "=== Building ownca-nginx:latest ==="
        ctx="$(stage_build_context "${REPO_ROOT}/dev_env/nginx" "${NGINX_FILES[@]}")"
        docker build \
            -f "${REPO_ROOT}/dev_env/nginx/Dockerfile" \
            -t ownca-nginx:latest "${ctx}"
    fi

    if is_selected "ownca-dashboard:latest"; then
        echo ""
        echo "=== Building ownca-dashboard:latest ==="
        ctx="$(stage_build_context "${REPO_ROOT}" "${DASHBOARD_FILES[@]}")"
        docker build \
            -f "${REPO_ROOT}/dev_env/dashboard/Dockerfile" \
            -t ownca-dashboard:latest "${ctx}"
    fi

    echo ""
    echo "=== Images built ==="
    docker images --format "  {{.Repository}}:{{.Tag}}  {{.Size}}" \
        | grep -E "^  (ownca-|postgres)" || true
}

# Files/dirs shipped to the target host in the export tarball.
# Whitelist: anything not listed here stays out (build sources, docs, dev
# tooling, .git, etc.).
DEPLOY_PATHS=(
    build-images.sh
    docker-compose.yml
    init-db.sh
    nginx.conf
    README.md
    README.en.md
)

export_images() {
    local IMAGES
    IMAGES="$(selected_images_list)"
    echo "=== Saving Docker images to ${DOCKER_IMAGES_TAR} ==="
    echo "  images: ${IMAGES}"
    docker save ${IMAGES} > "${SCRIPT_DIR}/${DOCKER_IMAGES_TAR}"

    echo "=== Creating archive (deploy files + Docker images) ==="
    local TMPARCHIVE
    TMPARCHIVE="$(mktemp "$(dirname "${SCRIPT_DIR}")/.ownca-images.XXXXXX.tar.gz")"

    local tar_entries=()
    for p in "${DEPLOY_PATHS[@]}"; do
        tar_entries+=("${REPO_NAME}/${p}")
    done
    tar_entries+=("${REPO_NAME}/${DOCKER_IMAGES_TAR}")

    tar czf "${TMPARCHIVE}" \
        -C "$(dirname "${SCRIPT_DIR}")" \
        "${tar_entries[@]}"

    mv "${TMPARCHIVE}" "${ARCHIVE}"
    rm -f "${SCRIPT_DIR}/${DOCKER_IMAGES_TAR}"
    echo "  $(du -h "${ARCHIVE}" | cut -f1)  ${ARCHIVE}"
    echo "=== Export done ==="
}

import_images() {
    if [ ! -f "${SCRIPT_DIR}/${DOCKER_IMAGES_TAR}" ]; then
        echo "ERROR: ${DOCKER_IMAGES_TAR} not found in ${SCRIPT_DIR}."
        echo "Extract the archive first:"
        echo "  tar xzf ownca-images.tar.gz -C /opt/"
        echo "  cd /opt/${REPO_NAME}"
        echo "  bash build-images.sh import"
        exit 1
    fi
    echo "=== Loading Docker images from ${DOCKER_IMAGES_TAR} ==="
    docker load < "${SCRIPT_DIR}/${DOCKER_IMAGES_TAR}"
    rm -f "${SCRIPT_DIR}/${DOCKER_IMAGES_TAR}"
    echo ""
    echo "=== Images loaded ==="
    docker images --format "  {{.Repository}}:{{.Tag}}  {{.Size}}" \
        | grep -E "^  (ownca-|postgres)" || true
    echo ""
    echo "Now run:  docker compose up -d"
}

CMD="${1:-build}"
shift 2>/dev/null || true
parse_selection "$@"

case "${CMD}" in
    build)
        build_images
        ;;
    export)
        export_images
        ;;
    import)
        import_images
        ;;
    all)
        build_images
        echo ""
        export_images
        ;;
    help|-h|--help)
        show_help
        ;;
    *)
        echo "Unknown command: ${CMD}"
        echo ""
        show_help
        exit 1
        ;;
esac
