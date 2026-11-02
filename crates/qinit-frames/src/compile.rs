// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The compile pipeline (spec §7): layers to database bytes, checked by the proved validator.
//!
//! Stages, in order: `layers::load` and `layers::load_enable`, `expand`, `resolve`,
//! `policy::check` (when a policy file is given), the graph passes, `qinit_db::write`, then the
//! self-check (`qinit_db::open` and `decode`, compared with the model) and the dump. A stage that
//! fails returns every error it found; later stages do not run.
use crate::error::{Code, Error, Warning};
use crate::expand::{expand, with_layer};
use crate::layers::{self, LayerInput};
use crate::resolve::resolve;
use crate::{dump, graph, policy};
use qinit_db::Model;
use std::path::PathBuf;

/// What to compile: the layers in order (later amends earlier) and an optional policy file.
#[derive(Clone, Debug)]
pub struct CompileInput {
    pub layers: Vec<LayerInput>,
    pub policy: Option<PathBuf>,
}

/// A compiled database, the non-fatal findings and a human-readable dump with provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    pub bytes: Vec<u8>,
    pub warnings: Vec<Warning>,
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
    let located =
        |es: Vec<Error>| -> Vec<Error> { es.into_iter().map(|e| with_layer(prov, e)).collect() };
    if let Some(path) = &input.policy {
        let p = policy::load_policy(path)?;
        policy::check(&p, &resolved.model).map_err(located)?;
    }
    graph::check(&resolved.model).map_err(|e| located(vec![e]))?;
    let bytes = self_checked(&resolved.model).map_err(|e| vec![e])?;
    Ok(Compiled {
        bytes,
        warnings: resolved.warnings,
        dump: dump::render(&resolved.model, prov),
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
