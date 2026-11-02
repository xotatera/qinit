// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Compiles a fixture with the real frame compiler, so every scenario runs the whole pipeline.
#![allow(dead_code)] // each test binary uses a different part of the helpers

use qinit_colony::sim::{Sim, advance};
use qinit_colony::{Colony, Notice, Outcome};
use qinit_frames::compile::{CompileInput, compile};
use qinit_frames::layers::LayerInput;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A throwaway directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "qinit-colony-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The directory holding the fixtures.
pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Compiles the frames in `frames` (a fixture file name or inline TOML if it holds a newline)
/// with `enable` as the roots, and returns the database bytes.
pub fn database(frames: &str, enable: &[&str]) -> Vec<u8> {
    let tmp = TempDir::new();
    let vendor = tmp.0.join("vendor");
    std::fs::create_dir_all(&vendor).expect("layer dir");
    let body = if frames.contains('\n') {
        frames.to_owned()
    } else {
        std::fs::read_to_string(fixtures().join(frames)).expect("fixture")
    };
    std::fs::write(vendor.join("frames.toml"), body).expect("frames");
    let list: Vec<String> = enable.iter().map(|e| format!("\"{e}\"")).collect();
    std::fs::write(
        vendor.join("enable.toml"),
        format!("enable = [{}]\n", list.join(", ")),
    )
    .expect("enable");
    let input = CompileInput {
        layers: vec![LayerInput {
            name: "vendor".to_owned(),
            dir: vendor,
        }],
        policy: None,
    };
    compile(&input).expect("fixture compiles").bytes
}

/// A colony over `frames`, loaded at time 0 against a fresh simulation.
pub fn boot(frames: &str, enable: &[&str], sim: Sim) -> (Colony<Sim>, Outcome) {
    Colony::load(database(frames, enable), &[], sim, 0).expect("loads")
}

/// The index of `name`.
pub fn idx(c: &Colony<Sim>, name: &str) -> u32 {
    c.node_index(name)
        .unwrap_or_else(|| panic!("no node {name}"))
}

/// The names of the nodes in the order the simulation was asked to start them.
pub fn start_order(c: &Colony<Sim>) -> Vec<String> {
    c.effects
        .calls
        .iter()
        .filter_map(|call| match call {
            qinit_colony::sim::Call::Start(n) => Some(c.model().nodes[*n as usize].name.clone()),
            _ => None,
        })
        .collect()
}

/// Lets `ms` milliseconds of virtual time pass.
pub fn pass(c: &mut Colony<Sim>, ms: u64) -> Vec<Notice> {
    advance(c, ms)
}
