// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Helpers shared by the integration tests.
#![allow(dead_code)] // each test file uses a subset of the helpers
use qinit_db::Model;
use qinit_frames::compile::CompileInput;
use qinit_frames::error::Error;
use qinit_frames::expand::expand;
use qinit_frames::layers::LayerInput;
use qinit_frames::layers::{Enable, Merged};
use qinit_frames::provenance::{FrameKey, Provenance};
use qinit_frames::resolve::{Resolved, resolve};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn merged(src: &str) -> Merged {
    Merged {
        table: src.parse::<toml::Table>().expect("test toml"),
        provenance: BTreeMap::new(),
    }
}

/// The layer that set `keys` of frame `kind.name`, by exact key.
pub fn set_in<'a>(prov: &'a Provenance, kind: &str, name: &str, keys: &[&str]) -> Option<&'a str> {
    prov.get(&FrameKey::new(kind, name, keys))
        .map(|o| o.layer.as_str())
}

pub fn enable(roots: &[&str], syslog: &[&str]) -> Enable {
    Enable {
        roots: roots.iter().map(|s| (*s).to_string()).collect(),
        syslog: syslog.iter().map(|s| (*s).to_string()).collect(),
    }
}

pub fn run(src: &str, en: &Enable) -> Result<Resolved, Vec<Error>> {
    let e = expand(&merged(src))?;
    resolve(&e, en)
}

pub fn ok(src: &str) -> Resolved {
    run(src, &Enable::default()).expect("resolves")
}

pub fn errs(src: &str) -> Vec<Error> {
    run(src, &Enable::default()).expect_err("refused")
}

pub fn idx(m: &Model, name: &str) -> u32 {
    let i = m.nodes.iter().position(|n| n.name == name).expect("node");
    u32::try_from(i).expect("index")
}

pub fn node<'a>(m: &'a Model, name: &str) -> &'a qinit_db::Node {
    &m.nodes[idx(m, name) as usize]
}

/// A unique scratch directory, removed on drop (also when the test panics).
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// A fresh, empty directory unique to `tag`, this process and this call.
    pub fn new(tag: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("qinit-frames-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("mkdir temp dir");
        Self { path }
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A throwaway directory of layers, removed on drop.
pub struct Tree {
    pub root: PathBuf,
    _dir: TempDir,
}

impl Tree {
    /// A fresh, empty tree unique to `tag` and this process.
    pub fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        Self {
            root: dir.to_path_buf(),
            _dir: dir,
        }
    }

    /// Write `body` to `<layer>/<file>`.
    pub fn file(&self, layer: &str, file: &str, body: &str) -> &Self {
        let dir = self.root.join(layer);
        std::fs::create_dir_all(&dir).expect("mkdir layer");
        std::fs::write(dir.join(file), body).expect("write frame");
        self
    }

    /// The compile input over `layers` in order, creating any empty layer directory.
    pub fn input(&self, layers: &[&str]) -> CompileInput {
        compile_input(&self.root, layers)
    }
}

/// The compile input over `root/<layer>` for each of `layers`, without a policy.
pub fn compile_input(root: &Path, layers: &[&str]) -> CompileInput {
    let layers = layers
        .iter()
        .map(|l| {
            let dir = root.join(l);
            std::fs::create_dir_all(&dir).expect("mkdir layer");
            LayerInput {
                name: (*l).to_string(),
                dir,
            }
        })
        .collect();
    CompileInput {
        layers,
        policy: None,
    }
}

/// The golden tree shipped with the tests.
pub fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// The compile input of the golden tree: layers `vendor` then `etc`.
pub fn golden_input() -> CompileInput {
    compile_input(&golden_dir(), &["vendor", "etc"])
}
