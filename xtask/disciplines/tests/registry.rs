// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The registry's exact order is pinned: a gate removed, renamed or reordered
//! retires a layer while every remaining gate keeps passing.
use std::collections::HashSet;

use xtask::Inputs;

#[test]
fn registry_order_is_pinned() {
    let names: Vec<&str> = xtask::registry().iter().map(|g| g.name).collect();
    assert_eq!(
        names,
        [
            "preflight",
            "fmt",
            "placeholder-scan", // disciplines:allow-placeholder (the gate's name)
            "sleep-scan",
            "changelog",
            "lint",
            "layers",
            "no-std",
            "duplication",
            "test"
        ]
    );
}

#[test]
fn names_are_unique_and_non_empty() {
    let names: Vec<&str> = xtask::registry().iter().map(|g| g.name).collect();
    assert!(names.iter().all(|n| !n.is_empty()));
    assert_eq!(names.iter().collect::<HashSet<_>>().len(), names.len());
}

const PREFLIGHT_TOOLS: &[&str] = &[
    "cargo",
    "rustfmt",
    "cargo-clippy",
    "git",
    "verus",
    "verusfmt",
];

type Decl = (
    &'static str,
    Inputs,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
    bool,
    bool,
);

#[test]
fn cache_declarations_are_pinned() {
    const RUST_ENV: &[&str] = &[
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CLIPPY_CONF_DIR",
    ];
    let got: Vec<Decl> = xtask::registry()
        .iter()
        .map(|g| {
            (
                g.name,
                g.inputs,
                g.env,
                g.tools,
                g.extra_paths,
                g.ignored_inputs,
                g.cacheable,
                g.cache_on_main,
            )
        })
        .collect();
    let mut want: Vec<Decl> = vec![
        (
            "preflight",
            Inputs::Globs(&["**/Cargo.toml"]),
            &[],
            PREFLIGHT_TOOLS,
            &[],
            &[],
            true,
            true,
        ),
        (
            "fmt",
            Inputs::Globs(&[
                "**/*.rs",
                "**/rustfmt.toml",
                "**/.rustfmt.toml",
                "**/Cargo.toml",
            ]),
            &["RUSTFMT"],
            &["cargo", "rustfmt", "verusfmt"],
            &[],
            &[],
            true,
            false,
        ),
        (
            "lint",
            Inputs::Tree,
            RUST_ENV,
            &["cargo", "cargo-clippy", "rustc"],
            &[],
            &[],
            true,
            false,
        ),
        (
            "layers",
            Inputs::Tree,
            RUST_ENV,
            &["cargo"],
            &[],
            &[],
            true,
            false,
        ),
        (
            "no-std",
            Inputs::Tree,
            RUST_ENV,
            &["cargo", "rustc"],
            &[],
            &[],
            true,
            false,
        ),
        (
            "duplication",
            Inputs::Globs(&["**/*.rs", "gates/duplication-baseline.txt"]),
            &[],
            &["git"],
            &[],
            &[],
            true,
            true,
        ),
        (
            "test",
            Inputs::Tree,
            RUST_ENV,
            &["cargo", "rustc"],
            &[],
            &[],
            true,
            false,
        ),
    ];
    // After preflight and fmt.
    want.splice(2..2, scan_declarations());
    assert_eq!(got, want);
}

/// The whole-tree text scans' declarations, in registry order.
fn scan_declarations() -> Vec<Decl> {
    vec![
        (
            "placeholder-scan", // disciplines:allow-placeholder (the gate's name)
            Inputs::Tree,
            &[],
            &["git"],
            &[],
            &[],
            true,
            true,
        ),
        (
            "sleep-scan",
            Inputs::Tree,
            &[],
            &["git"],
            &[],
            &[],
            true,
            true,
        ),
        // Refs decide it: never cached.
        (
            "changelog",
            Inputs::Tree,
            &[],
            &["git"],
            &[],
            &[],
            false,
            false,
        ),
    ]
}

#[test]
fn preflight_fingerprints_every_required_tool() {
    let preflight = xtask::registry()
        .into_iter()
        .find(|g| g.name == "preflight")
        .unwrap();
    let mut required: Vec<&str> = xtask::tools::REQUIRED.iter().map(|(t, _)| *t).collect();
    // The tool preflight requires once a Verus entry is declared.
    required.extend(["verus", "verusfmt"]);
    assert_eq!(preflight.tools, required.as_slice());
    let declared = xtask::proofs::parse(PROOF_METADATA).unwrap();
    for (tool, _) in xtask::proofs::required_tools(&declared.proofs) {
        assert!(preflight.tools.contains(&tool), "{tool}");
    }
}

#[test]
fn only_fmt_and_no_std_carry_a_blocked_switch() {
    for g in xtask::registry() {
        let expected = match g.name {
            "fmt" => xtask::fmt_gate::BLOCKED,
            "no-std" => xtask::layers::NO_STD_BLOCKED,
            _ => None,
        };
        assert_eq!(g.blocked, expected, "{}", g.name);
    }
}

const PROOF_METADATA: &str = r#"{"workspace_root": "/ws", "target_directory": "/ws/target",
  "packages": [{"name": "a", "manifest_path": "/ws/crates/a/Cargo.toml", "dependencies": []}],
  "metadata": {"disciplines": {"proof": [{"name": "core", "kind": "kani", "package": "a", "memory": "4G"},
    {"name": "spine", "kind": "verus", "package": "a", "memory": "2G"}]}}}"#;

const COMMAND_METADATA: &str = r#"{"workspace_root": "/ws",
  "packages": [{"name": "a", "manifest_path": "/ws/crates/a/Cargo.toml", "dependencies": []}],
  "metadata": {"disciplines": {"proof": [{"name": "core", "kind": "command",
    "command": ["verus-wrapper", "verify"], "package": "a", "memory": "4G"}]}}}"#;

#[test]
fn every_static_gate_has_no_declaration() {
    assert!(xtask::registry().iter().all(|g| g.decl.is_empty()));
}

#[test]
fn a_proof_gate_is_keyed_narrowly_and_trusted_on_main() {
    let declared = xtask::proofs::parse(PROOF_METADATA).unwrap();
    let gate = xtask::proof_gate(declared.proofs[0].clone(), 8 << 30, None);
    assert_eq!(gate.name, "proof:core");
    assert_eq!(
        gate.inputs,
        xtask::Inputs::Globs(&[
            "crates/a/**",
            "Cargo.lock",
            "rust-toolchain.toml",
            "rust-toolchain"
        ])
    );
    assert!(gate.cacheable);
    assert!(gate.cache_on_main);
    assert_eq!(gate.blocked, None);
    assert!(gate.tools.contains(&"cargo") && gate.tools.contains(&"cargo-kani"));
    assert!(
        gate.tools.contains(&"timeout"),
        "kani runs under timeout too"
    );
    assert_eq!(gate.decl, declared.proofs[0].decl);
    let skipped = xtask::proof_gate(declared.proofs[0].clone(), 8 << 30, Some("--no-proofs"));
    assert_eq!(skipped.blocked, Some("--no-proofs"));
}

#[test]
fn a_command_proof_fingerprints_its_program() {
    let declared = xtask::proofs::parse(COMMAND_METADATA).unwrap();
    let gate = xtask::proof_gate(declared.proofs[0].clone(), 8 << 30, None);
    assert!(gate.tools.contains(&"verus-wrapper"));
    assert!(gate.tools.contains(&"prlimit") && gate.tools.contains(&"timeout"));
}

#[test]
fn a_proof_gate_carries_its_extra_paths_and_tools() {
    let json = COMMAND_METADATA.replace(
        r#""memory": "4G"}"#,
        r#""memory": "4G", "extra_paths": ["~/verus"], "tools": ["verus"]}"#,
    );
    let declared = xtask::proofs::parse(&json).unwrap();
    let gate = xtask::proof_gate(declared.proofs[0].clone(), 8 << 30, None);
    assert_eq!(gate.extra_paths, &["~/verus"]);
    assert!(gate.tools.contains(&"verus"));
}
