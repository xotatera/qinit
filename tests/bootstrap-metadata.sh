# SPDX-FileCopyrightText: 2026 Xota Tera
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Checks the repository bootstrap without depending on the later xtask runner.

set -eu

failures=0
repo_root=$(pwd)

fail() {
    printf '%s\n' "FAIL: $1" >&2
    failures=$((failures + 1))
}

require_file() {
    if [ ! -f "$1" ]; then
        fail "missing $1"
    fi
}

matches_pinned_toolchain() (
    unset RUSTUP_TOOLCHAIN
    cd "$1"
    actual=$(rustc --version) || exit 1
    case "$actual" in
        'rustc 1.98.1 '*) ;;
        *)
            printf '%s\n' "expected Rust 1.98.1, got: $actual" >&2
            exit 1
            ;;
    esac
)

pinned_tools_execute() (
    unset RUSTUP_TOOLCHAIN
    cd "$1"
    rustfmt --version >/dev/null
    cargo clippy --version >/dev/null
)

copy_bootstrap_fixture() {
    fixture=$1
    mkdir -p "$fixture/.cargo"
    cp "$repo_root/Cargo.toml" "$repo_root/rust-toolchain.toml" "$repo_root/README.md" \
        "$fixture/"
    cp "$repo_root/.cargo/config.toml" "$fixture/.cargo/config.toml"
}

configured_xtask_alias_runs() (
    unset RUSTUP_TOOLCHAIN
    source_root=$1
    fixture=$(mktemp -d)
    trap 'rm -rf "$fixture"' EXIT HUP INT TERM

    mkdir -p "$fixture/.cargo" "$fixture/xtask/runner/src"
    cp "$source_root/Cargo.toml" "$source_root/rust-toolchain.toml" "$fixture/"
    cp "$source_root/.cargo/config.toml" "$fixture/.cargo/config.toml"
    cat >"$fixture/xtask/Cargo.toml" <<'EOF'
[workspace]
members = ["runner"]
resolver = "3"
EOF
    cat >"$fixture/xtask/runner/Cargo.toml" <<'EOF'
[package]
name = "qinit-xtask"
version = "0.0.0"
edition = "2024"
EOF
    cat >"$fixture/xtask/runner/src/main.rs" <<'EOF'
fn main() {
    assert_eq!(std::env::args().nth(1).as_deref(), Some("alias-probe"));
    println!("qinit-xtask-alias-probe");
}
EOF

    output=$(cd "$fixture" && CARGO_TARGET_DIR="$fixture/target" cargo xtask alias-probe)
    test "$output" = 'qinit-xtask-alias-probe'
)

require_file Cargo.toml
require_file rust-toolchain.toml
require_file .cargo/config.toml
require_file README.md

if [ -f Cargo.toml ]; then
    grep -Fqx '[workspace]' Cargo.toml || fail 'Cargo.toml must declare [workspace]'
    grep -Fqx 'resolver = "3"' Cargo.toml || fail 'Cargo.toml must set resolver = "3"'
fi

if [ -f rust-toolchain.toml ]; then
    grep -Fqx 'channel = "1.98.1"' rust-toolchain.toml \
        || fail 'rust-toolchain.toml must pin Rust 1.98.1'
    grep -Fqx 'components = ["rustfmt", "clippy"]' rust-toolchain.toml \
        || fail 'rust-toolchain.toml must declare rustfmt and clippy components'
    matches_pinned_toolchain "$repo_root" \
        || fail 'rust-toolchain.toml must select the pinned Rust toolchain'
    pinned_tools_execute "$repo_root" \
        || fail 'the pinned rustfmt and clippy tools must execute'
fi

if [ -f .cargo/config.toml ]; then
    grep -Fqx 'xtask = "run --manifest-path xtask/Cargo.toml --package qinit-xtask --quiet --"' \
        .cargo/config.toml || fail '.cargo/config.toml must define the cargo xtask alias'
    configured_xtask_alias_runs "$repo_root" \
        || fail 'Cargo must load the configured xtask alias'
fi

canary=$(mktemp)
alias_fixture=$(mktemp -d)
pin_fixture=$(mktemp -d)
trap 'rm -f "$canary"; rm -rf "$alias_fixture" "$pin_fixture"' EXIT HUP INT TERM
printf '%s\n' \
    '> [!IMPORTANT]' \
    '> Remove these two lines to confirm that a human has reviewed this change.' \
    >"$canary"
if ! head -n 2 README.md | cmp -s "$canary" -; then
    fail 'README.md must begin with the review canary byte-for-byte'
fi

grep -Fqx 'Status: design only. qinit is not usable yet.' README.md \
    || fail 'README.md must state that qinit is not usable'
grep -Fqx 'There is no CI at this stage.' README.md \
    || fail 'README.md must not claim that CI exists'
grep -Fqx 'cargo xtask gate --no-cache' README.md \
    || fail 'README.md must name the uncached full gate command'
grep -Fqx 'The committed hooks are opt-in; install them only in a clone where you want local checks.' README.md \
    || fail 'README.md must explain that hooks are opt-in'
grep -Fqx 'sh .githooks/setup-hooks.sh' README.md \
    || fail 'README.md must name the hook installation command'
grep -Fqx "The selected Verus release is \`0.2026.10.04.426d8b0\`; the tooling preflight" README.md \
    || fail 'README.md must state the selected Verus release'
grep -Fqx "verifies it with \`verus --version\` when a \`kind = \"verus\"\` proof is declared." README.md \
    || fail 'README.md must state when the selected Verus release is asserted'
grep -Fqx 'existing hooks rather than claiming they are protected. It copies qinit-owned' README.md \
    || fail 'README.md must describe only conflicting hook names as refused'

copy_bootstrap_fixture "$alias_fixture"
sed 's|run --manifest-path xtask/Cargo.toml --package qinit-xtask --quiet --|run --package qinit-xtask --quiet --|' \
    "$alias_fixture/.cargo/config.toml" >"$alias_fixture/.cargo/config.toml.new"
mv "$alias_fixture/.cargo/config.toml.new" "$alias_fixture/.cargo/config.toml"
if configured_xtask_alias_runs "$alias_fixture" >/dev/null 2>&1; then
    fail 'broken xtask alias negative control unexpectedly passed'
fi

copy_bootstrap_fixture "$pin_fixture"
sed 's/channel = "1.98.1"/channel = "1.83.0"/' "$pin_fixture/rust-toolchain.toml" \
    >"$pin_fixture/rust-toolchain.toml.new"
mv "$pin_fixture/rust-toolchain.toml.new" "$pin_fixture/rust-toolchain.toml"
if matches_pinned_toolchain "$pin_fixture" >/dev/null 2>&1; then
    fail 'wrong Rust pin negative control unexpectedly passed'
fi

printf '%s\n' 'PASS: behavioral negative controls'

if [ "$failures" -ne 0 ]; then
    exit 1
fi

printf '%s\n' 'PASS: bootstrap metadata'
