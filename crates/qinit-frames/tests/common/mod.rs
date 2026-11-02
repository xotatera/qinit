// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Helpers shared by the resolve tests.
#![allow(dead_code, reason = "each test file uses a subset")]
use qinit_db::Model;
use qinit_frames::error::Error;
use qinit_frames::expand::expand;
use qinit_frames::layers::{Enable, Merged};
use qinit_frames::resolve::{Resolved, resolve};
use std::collections::BTreeMap;

pub fn merged(src: &str) -> Merged {
    Merged {
        table: src.parse::<toml::Table>().expect("test toml"),
        provenance: BTreeMap::new(),
    }
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
