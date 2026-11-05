// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! `qctl compile`: layers to a database file, written atomically.
use crate::args::{CompileOpts, PolicyChoice};
use crate::{owner, report};
use qinit_frames::compile::{CompileInput, compile};
use qinit_frames::layers::LayerInput;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The paths used when an option is not given.
#[derive(Clone, Debug)]
pub struct Defaults {
    /// The `vendor` layer.
    pub vendor: PathBuf,
    /// The `etc` layer; may be absent.
    pub etc: PathBuf,
    /// The policy file; used when it exists.
    pub policy: PathBuf,
    /// The effective user id the ownership check goes by; a test injects it.
    pub euid: u32,
}

impl Defaults {
    /// The system paths.
    #[must_use]
    pub fn system() -> Self {
        Self {
            vendor: "/usr/lib/qinit/frames".into(),
            etc: "/etc/qinit/frames".into(),
            policy: "/etc/qinit/policy.toml".into(),
            euid: owner::geteuid(),
        }
    }
}

/// The result of choosing layers and policy: the compiler input.
///
/// # Errors
/// A named layer or policy file that is absent.
pub fn input(
    layers: &[(String, PathBuf)],
    policy: &PolicyChoice,
    defaults: &Defaults,
    err: &mut dyn Write,
) -> Result<CompileInput, String> {
    let mut chosen = Vec::new();
    if layers.is_empty() {
        if !defaults.vendor.is_dir() {
            return Err(format!(
                "layer vendor: {}: no such directory",
                defaults.vendor.display()
            ));
        }
        chosen.push(LayerInput {
            name: "vendor".into(),
            dir: defaults.vendor.clone(),
        });
        if defaults.etc.is_dir() {
            chosen.push(LayerInput {
                name: "etc".into(),
                dir: defaults.etc.clone(),
            });
        } else {
            let _ = writeln!(
                err,
                "qctl: etc layer {} absent, taken as empty",
                defaults.etc.display()
            );
        }
    } else {
        for (name, dir) in layers {
            if !dir.is_dir() {
                return Err(format!(
                    "layer {name}: {}: no such directory",
                    dir.display()
                ));
            }
            chosen.push(LayerInput {
                name: name.clone(),
                dir: dir.clone(),
            });
        }
    }
    let policy = match policy {
        PolicyChoice::None => None,
        PolicyChoice::File(f) => {
            if !f.is_file() {
                return Err(format!("policy {}: no such file", f.display()));
            }
            Some(f.clone())
        }
        PolicyChoice::Default => {
            if defaults.policy.is_file() {
                let _ = writeln!(err, "qctl: policy {}", defaults.policy.display());
                Some(defaults.policy.clone())
            } else {
                let _ = writeln!(
                    err,
                    "qctl: no policy file {}, compiling without a policy check",
                    defaults.policy.display()
                );
                None
            }
        }
    };
    Ok(CompileInput {
        layers: chosen,
        policy,
    })
}

/// The compiler input of `layers` and `policy` after the ownership check (spec §4.4) of every
/// layer and the policy file, for every command that reads frames.
///
/// # Errors
/// The exit code, 1, once the reason is on `err`: a named layer or policy file is absent, or
/// (as root) a path fails the ownership check.
pub fn checked_input(
    layers: &[(String, PathBuf)],
    policy: &PolicyChoice,
    defaults: &Defaults,
    err: &mut dyn Write,
) -> Result<CompileInput, i32> {
    let input = input(layers, policy, defaults, err).map_err(|m| {
        let _ = writeln!(err, "qctl: {m}");
        1
    })?;
    let mut roots: Vec<&Path> = input.layers.iter().map(|l| l.dir.as_path()).collect();
    roots.extend(input.policy.as_deref());
    owner::check(&roots, defaults.euid, err).map_err(|r| {
        let _ = writeln!(err, "{r}");
        1
    })?;
    Ok(input)
}

/// Run `qctl compile`; returns the exit code.
pub fn run(
    opts: &CompileOpts,
    defaults: &Defaults,
    _out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let input = match checked_input(&opts.layers, &opts.policy, defaults, err) {
        Ok(i) => i,
        Err(code) => return code,
    };
    let compiled = match compile(&input) {
        Ok(c) => c,
        Err(errors) => {
            for e in &errors {
                let _ = writeln!(err, "{}", report::error_line(e));
            }
            return 1;
        }
    };
    for w in &compiled.warnings {
        let _ = writeln!(err, "{}", report::warning_line(w));
    }
    let output = &opts.output;
    if let Err(e) = write_atomic(output, &compiled.bytes) {
        let _ = writeln!(err, "qctl: {}: {e}", output.display());
        return 1;
    }
    if let Some(dump) = &opts.dump
        && let Err(e) = write_atomic(dump, compiled.dump.as_bytes())
    {
        let _ = writeln!(err, "qctl: {}: {e}", dump.display());
        return 1;
    }
    0
}

/// Write `bytes` to a temporary file beside `path` (mode 0644) and rename it over.
///
/// # Errors
/// Any I/O error; the temporary file is removed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
