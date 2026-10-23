// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! qinit's binary preserves proof declaration errors and treats no proofs as a no-op.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn xtask(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qinit-xtask"))
        .args(arguments)
        .output()
        .expect("spawn qinit-xtask")
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("qinit-xtask-cli-{nonce}"));
        std::fs::create_dir_all(&root).unwrap();
        let archive = root.join("xtask.tar");
        let archived = Command::new("git")
            .args(["archive", "--format=tar", "--output"])
            .arg(&archive)
            .args(["HEAD", "xtask"])
            .current_dir(qinit_xtask::repo_root())
            .status()
            .expect("archive checked-in xtask fixture");
        assert!(archived.success());
        let extracted = Command::new("tar")
            .args([
                "-xf",
                archive.to_str().unwrap(),
                "-C",
                root.to_str().unwrap(),
            ])
            .status()
            .expect("extract xtask fixture");
        assert!(extracted.success());
        std::fs::remove_file(archive).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\nresolver = \"3\"\n").unwrap();
        std::fs::write(
            root.join("README.md"),
            "> [!IMPORTANT]\n> Remove these two lines to confirm that a human has reviewed this change.\n",
        )
        .unwrap();
        Self { root }
    }

    fn malformed_root_proofs() -> Self {
        let fixture = Self::new();
        std::fs::write(
            fixture.root.join("Cargo.toml"),
            "[workspace]\nresolver = \"3\"\n\n[workspace.metadata.disciplines]\nproof = \"not a table\"\n",
        )
        .unwrap();
        fixture
    }

    fn malformed_tooling_proofs() -> Self {
        let fixture = Self::new();
        let manifest = fixture.root.join("xtask/Cargo.toml");
        let mut text = std::fs::read_to_string(&manifest).unwrap();
        text.push_str("\n[workspace.metadata.disciplines]\nproof = \"not a table\"\n");
        std::fs::write(manifest, text).unwrap();
        fixture
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new("cargo")
            .args([
                "run",
                "--manifest-path",
                self.root.join("xtask/Cargo.toml").to_str().unwrap(),
                "--package",
                "qinit-xtask",
                "--quiet",
                "--locked",
                "--offline",
                "--",
            ])
            .args(arguments)
            .current_dir(&self.root)
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .output()
            .expect("run fixture qinit-xtask")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn empty_proofs_are_a_successful_no_op() {
    let output = xtask(&["proofs"]);
    assert!(output.status.success(), "{:?}", output.status);
}

#[test]
fn unknown_proof_filter_still_errors() {
    let output = xtask(&["proofs", "--only", "missing"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown gate `proof:missing`"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn valid_tooling_fixture_accepts_gate_and_proofs() {
    let fixture = Fixture::new();
    let proofs = fixture.run(&["proofs"]);
    assert!(proofs.status.success(), "{:?}", proofs.status);
    let gate = fixture.run(&["gate", "--only", "xtask/preflight", "--no-cache"]);
    assert!(gate.status.success(), "{:?}", gate.status);
}

#[test]
fn full_gate_names_the_malformed_repository_proof_declaration() {
    let fixture = Fixture::malformed_root_proofs();
    let output = fixture.run(&["gate", "--no-cache"]);
    assert!(!output.status.success(), "{:?}", output.status);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("repo proofs: proof: expected"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn proofs_names_the_malformed_repository_proof_declaration() {
    let fixture = Fixture::malformed_root_proofs();
    let output = fixture.run(&["proofs"]);
    assert!(!output.status.success(), "{:?}", output.status);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("repo proofs: proof: expected"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn full_gate_names_the_malformed_tooling_proof_declaration() {
    let fixture = Fixture::malformed_tooling_proofs();
    let output = fixture.run(&["gate", "--no-cache"]);
    assert!(!output.status.success(), "{:?}", output.status);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("xtask proofs: proof: expected"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn proofs_names_the_malformed_tooling_proof_declaration() {
    let fixture = Fixture::malformed_tooling_proofs();
    let output = fixture.run(&["proofs"]);
    assert!(!output.status.success(), "{:?}", output.status);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("xtask proofs: proof: expected"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
