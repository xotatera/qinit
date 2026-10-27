#!/bin/sh
# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Portability check: clone this repository fresh inside a stock Debian stable
# container, install only the documented requirements (README, Requirements),
# and run the full gate as an unprivileged user. Anything the gate needs that
# the developer's machine supplies silently fails here.
#
#   sh scripts/container-check.sh [<ref>]    default: the current branch
#
# Uses podman, or docker when CONTAINER=docker.
set -eu
image='docker.io/library/debian@sha256:b52d043ed9ce0a3313d85dc03980d5496aa25dff2f05b032d470446b1e3e0e2a'
engine="${CONTAINER:-podman}"
top="$(git rev-parse --show-toplevel)"
common="$(git rev-parse --path-format=absolute --git-common-dir)"
ref="${1:-$(git symbolic-ref --short HEAD)}"
git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || {
    echo "container-check: unknown ref $ref" >&2
    exit 2
}
cd "$top"
# The script runs inside the container: its variables expand there.
# shellcheck disable=SC2016
exec "$engine" run --rm -v "$common:/src/qinit.git:ro" -e REF="$ref" "$image" sh -c '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl git build-essential reuse >/dev/null
useradd -m builder
su builder -c "
set -eu
git config --global --add safe.directory /src/qinit.git
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
. \"\$HOME/.cargo/env\"
git clone -q --branch \"$REF\" /src/qinit.git \"\$HOME/qinit\"
cd \"\$HOME/qinit\"
cargo xtask gate --no-cache
"
'
