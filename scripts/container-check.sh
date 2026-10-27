#!/bin/sh
# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Portability check: clone this repository fresh inside a stock Debian stable
# container, install only the documented requirements (README, Requirements),
# and run the full gate as an unprivileged user. Anything the gate needs that
# the developer's machine supplies silently fails here.
#
#   sh scripts/container-check.sh [<commit-ish>]    default: HEAD
#
# Uses podman, or docker when CONTAINER=docker.
set -eu
image='docker.io/library/debian@sha256:b52d043ed9ce0a3313d85dc03980d5496aa25dff2f05b032d470446b1e3e0e2a'
engine="${CONTAINER:-podman}"
common="$(git rev-parse --path-format=absolute --git-common-dir)"
ref="${1:-HEAD}"
# Only the resolved commit id (hex) reaches the container's shells.
sha="$(git rev-parse --verify --quiet "$ref^{commit}")" || {
    echo "container-check: $ref does not name a commit" >&2
    exit 2
}
# The changelog gate needs a branch: the named branch when <commit-ish> is
# one (HEAD on a branch included), else a local `container-check` branch.
branch="$(git rev-parse --abbrev-ref --verify --quiet "$ref")" || branch=HEAD
if [ "$branch" = HEAD ] || ! git show-ref --verify --quiet "refs/heads/$branch"; then
    branch=container-check
fi
case "$branch" in
*[!A-Za-z0-9._/-]*)
    echo "container-check: branch name $branch has characters this check does not pass on" >&2
    exit 2
    ;;
esac
# A fresh clone fetches only what refs reach.
if [ -z "$(git for-each-ref --contains "$sha" --count=1)" ]; then
    echo "container-check: no branch or tag contains $sha, so a fresh clone cannot fetch it; commit it to a branch first" >&2
    exit 2
fi
# The script runs inside the container: its variables expand there.
# shellcheck disable=SC2016
exec "$engine" run --rm -v "$common:/src/qinit.git:ro" -e SHA="$sha" -e BRANCH="$branch" "$image" sh -c '
set -eu
case "$SHA" in *[!0-9a-f]*) echo "container-check: bad commit id" >&2; exit 2 ;; esac
case "$BRANCH" in *[!A-Za-z0-9._/-]*) echo "container-check: bad branch name" >&2; exit 2 ;; esac
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl git build-essential reuse >/dev/null
useradd -m builder
su builder -c "
set -eu
git config --global --add safe.directory /src/qinit.git
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
. \"\$HOME/.cargo/env\"
git clone -q /src/qinit.git \"\$HOME/qinit\"
cd \"\$HOME/qinit\"
git checkout -q -B $BRANCH $SHA
cargo xtask gate --no-cache
"
'
