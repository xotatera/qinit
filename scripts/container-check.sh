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
# A branch is checked out by its name. Any other commit-ish gets a local
# `container-check` branch; for a commit already on main, pass `main` by
# name, since the changelog gate fails a branch that changes nothing.
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
# Pass KVM only when it opens read-write; QINIT_CHECK_KVM=0 exercises TCG.
set -- run --rm -v "$common:/src/qinit.git:ro" -e SHA="$sha" -e BRANCH="$branch"
if [ "${QINIT_CHECK_KVM:-1}" != 0 ] && ( exec 3<> /dev/kvm ) 2>/dev/null; then
    set -- "$@" --device /dev/kvm
fi
# The override is optional; without it the guest kernel is downloaded normally.
if [ -n "${QINIT_KERNEL_TARBALL:-}" ]; then
    if [ ! -f "$QINIT_KERNEL_TARBALL" ]; then
        echo "container-check: kernel tarball not found: $QINIT_KERNEL_TARBALL" >&2
        exit 2
    fi
    set -- "$@" -v "$QINIT_KERNEL_TARBALL:/src/kernel.tar.xz:ro" -e QINIT_KERNEL_TARBALL=/src/kernel.tar.xz
fi
# shellcheck disable=SC2016
exec "$engine" "$@" "$image" sh -c '
set -eu
case "$SHA" in *[!0-9a-f]*) echo "container-check: bad commit id" >&2; exit 2 ;; esac
case "$BRANCH" in *[!A-Za-z0-9._/-]*) echo "container-check: bad branch name" >&2; exit 2 ;; esac
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl git build-essential reuse \
    qemu-system-x86 make gcc flex bison bc perl libelf-dev xz-utils unzip >/dev/null
useradd -m builder
su builder -c "
set -eu
git config --global --add safe.directory /src/qinit.git
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
. \"\$HOME/.cargo/env\"
curl -fsSL -o /tmp/verus.zip https://github.com/verus-lang/verus/releases/download/release/0.2026.10.04.426d8b0/verus-0.2026.10.04.426d8b0-x86-linux.zip
echo "624018662868563a7bec0dd07be5e4dd0c3d61124b4b55105765884bf2d4d1a0  /tmp/verus.zip" | sha256sum -c -
mkdir -p \"\$HOME/.local/opt\" \"\$HOME/.local/bin\"
unzip -q /tmp/verus.zip -d \"\$HOME/.local/opt\"
# The release archive contains verus-x86-linux/ (cargo-verus, verus, z3).
for t in cargo-verus verus z3; do ln -s \"\$HOME/.local/opt/verus-x86-linux/\$t\" \"\$HOME/.local/bin/\$t\"; done
export PATH=\"\$HOME/.local/bin:\$PATH\"
cargo install --locked verusfmt --version 0.7.4
if [ -f /src/kernel.tar.xz ]; then export QINIT_KERNEL_TARBALL=/src/kernel.tar.xz; fi
git clone -q /src/qinit.git \"\$HOME/qinit\"
cd \"\$HOME/qinit\"
git checkout -q -B $BRANCH $SHA
cargo xtask gate --no-cache
"
'
