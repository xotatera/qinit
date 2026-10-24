// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The fmt gate's migration switch.

/// `Some(reason)` keeps fmt registered but skipping (e.g. while a mass
/// reformat is pending). `tests/fmt_gate.rs` asserts `None`, so a skip cannot
/// outlive its migration unnoticed.
pub const BLOCKED: Option<&str> = None;

/// Whether verusfmt should see `text`: it names `verus!` anywhere (a
/// path-qualified `vstd::prelude::verus!` included). verusfmt passes a file
/// with nothing for it to format.
#[must_use]
pub fn invokes_verus(text: &str) -> bool {
    text.contains("verus!")
}

/// The 1-based lines where an indented `verus!` invocation starts. verusfmt
/// lays a block out from column 0 and rustfmt re-indents it, so no indented
/// block passes both: the gate asks for `verus!` at the top level.
#[must_use]
pub fn indented_verus(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let body = l.trim_start();
            body.len() < l.len()
                && (body.starts_with("verus!")
                    || body.split_once("::verus!").is_some_and(|(path, _)| {
                        path.chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == ':')
                    }))
        })
        .map(|(i, _)| i + 1)
        .collect()
}

/// What the fmt gate tells someone without verusfmt whose tree needs it.
pub const VERUSFMT_HINT: &str = "verusfmt is not on PATH: `cargo install --locked verusfmt` (it formats the code inside `verus!`, which rustfmt leaves alone)";
