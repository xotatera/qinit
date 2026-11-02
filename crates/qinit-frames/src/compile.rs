// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The compile pipeline (spec §7): layers to database bytes, checked by the proved validator.
//!
//! Stages, in order: `layers::load` and `layers::load_enable`, `expand`, `resolve`,
//! `policy::check` (when a policy file is given), the graph passes, `qinit_db::write`, then the
//! self-check (`qinit_db::open` and `decode`, compared with the model) and the dump. A stage that
//! fails returns every error it found; later stages do not run.
use crate::error::{Code, Error, Warning};
use crate::expand::{expand, kind_name};
use crate::layers::{self, LayerInput};
use crate::provenance::locate;
use crate::resolve::resolve;
use crate::{dump, graph, policy};
use qinit_db::Model;
use std::path::PathBuf;

/// What to compile: the layers in order (later amends earlier) and an optional policy file.
/// [`layers`] defines the amend rules.
#[derive(Clone, Debug)]
pub struct CompileInput {
    /// The layers, earliest first; each later layer amends the ones before it.
    pub layers: Vec<LayerInput>,
    /// The privilege policy file to check the credentials against; none means no check.
    pub policy: Option<PathBuf>,
}

/// A compiled database, the non-fatal findings and a human-readable dump with provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    /// The database, validated and decoded back to the resolved model before it is returned.
    pub bytes: Vec<u8>,
    /// Non-fatal findings, such as dropped optional edges.
    pub warnings: Vec<Warning>,
    /// The resolved model with the origin of each key; see [`crate::dump`].
    pub dump: String,
}

/// Compile `input` into database bytes.
///
/// # Errors
/// Every error of the first stage that fails. `SelfCheck` means the emitted bytes did not
/// validate or did not decode to the resolved model: a compiler bug, never a frame error.
pub fn compile(input: &CompileInput) -> Result<Compiled, Vec<Error>> {
    let (merged, enable) = match (
        layers::load(&input.layers),
        layers::load_enable(&input.layers),
    ) {
        (Ok(m), Ok(e)) => (m, e),
        (m, e) => {
            let mut errs = m.err().unwrap_or_default();
            errs.extend(e.err().unwrap_or_default());
            return Err(errs);
        }
    };
    let expanded = expand(&merged)?;
    let resolved = resolve(&expanded, &enable)?;
    let prov = &expanded.provenance;
    let model = &resolved.model;
    let located = |node: Option<usize>, mut e: Error| -> Error {
        if let Some(n) = node.and_then(|i| model.nodes.get(i)) {
            locate(prov, kind_name(n.kind), &n.name, &mut e);
        }
        e
    };
    if let Some(path) = &input.policy {
        let p = policy::load_policy(path)?;
        let errs: Vec<Error> = policy::violations(&p, model)
            .into_iter()
            .map(|(i, e)| located(Some(i), e))
            .collect();
        if !errs.is_empty() {
            return Err(errs);
        }
    }
    graph::check(model).map_err(|(i, e)| vec![located(i, e)])?;
    let bytes = self_checked(&resolved.model).map_err(|e| vec![e])?;
    let dump = dump::render(&resolved, prov);
    Ok(Compiled {
        bytes,
        warnings: resolved.warnings,
        dump,
    })
}

/// Write `model`, then open, validate and decode the bytes and compare with `model`.
fn self_checked(model: &Model) -> Result<Vec<u8>, Error> {
    let fail = |why: String| Error::new(Code::SelfCheck, "", why);
    let bytes = qinit_db::write(model).map_err(|e| fail(format!("write refused: {e:?}")))?;
    let decoded = qinit_db::open(&bytes)
        .map_err(|e| fail(format!("the emitted bytes do not validate: {e:?}")))?
        .decode();
    if decoded != *model {
        return Err(fail("the emitted bytes decode to a different model".into()));
    }
    Ok(bytes)
}
