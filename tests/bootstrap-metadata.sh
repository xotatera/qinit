# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Checks the repository bootstrap without depending on the later xtask runner.

set -eu

failures=0

fail() {
    printf '%s\n' "FAIL: $1" >&2
    failures=$((failures + 1))
}

require_file() {
    if [ ! -f "$1" ]; then
        fail "missing $1"
    fi
}

require_file Cargo.toml
require_file rust-toolchain.toml
require_file .cargo/config.toml
require_file README.md

if [ -f Cargo.toml ]; then
    grep -Fqx '[workspace]' Cargo.toml || fail 'Cargo.toml must declare [workspace]'
    grep -Eq '^resolver = "3"$' Cargo.toml || fail 'Cargo.toml must set resolver = "3"'
fi

if [ -f rust-toolchain.toml ]; then
    grep -Eq '^channel = "[0-9]+\.[0-9]+\.[0-9]+"$' rust-toolchain.toml \
        || fail 'rust-toolchain.toml must pin a Rust release'
    grep -Fq '"rustfmt"' rust-toolchain.toml \
        || fail 'rust-toolchain.toml must include rustfmt'
    grep -Fq '"clippy"' rust-toolchain.toml \
        || fail 'rust-toolchain.toml must include clippy'
fi

if [ -f .cargo/config.toml ]; then
    grep -Eq '^xtask = "run .*"$' .cargo/config.toml \
        || fail '.cargo/config.toml must define the cargo xtask alias'
fi

canary=$(mktemp)
trap 'rm -f "$canary"' EXIT HUP INT TERM
printf '%s\n' \
    '> [!IMPORTANT]' \
    '> Remove these two lines to confirm that a human has reviewed this change.' \
    >"$canary"
if ! head -n 2 README.md | cmp -s "$canary" -; then
    fail 'README.md must begin with the review canary byte-for-byte'
fi

if [ "$failures" -ne 0 ]; then
    exit 1
fi

printf '%s\n' 'PASS: bootstrap metadata'
