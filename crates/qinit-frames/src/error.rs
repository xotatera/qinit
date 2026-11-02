// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Stable error codes and the error and warning records of the frame compiler.
use std::path::PathBuf;

/// Stable error code; one per failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// A file or directory could not be read.
    Io,
    /// A file is not valid TOML.
    Parse,
    /// A key the schema does not know.
    UnknownKey,
    /// A frame defined twice in one layer.
    DuplicateFrame,
    /// A value of the wrong type or outside its allowed set, or a key the frame kind forbids.
    BadValue,
    /// A list change (`append`, `remove`, `replace`) that cannot be applied.
    ListOp,
    /// A frame or instance name outside the name alphabet or length.
    BadName,
    /// A reference to a frame that does not exist.
    MissingTarget,
    /// One name used by two frames of different kinds.
    DuplicateName,
    /// A missing template, or a template naming a template.
    Template,
    /// A bad `instances` list: empty, or an instance given twice.
    Instance,
    /// A credential set the privilege policy refuses.
    Policy,
    /// A table of the database would exceed its limit.
    Limit,
    /// The ordering edges form a cycle, or a worker logs to itself.
    Cycle,
    /// `stop = "parallel"` on a hard (sync require) edge.
    HardParallel,
    /// The emitted bytes failed the compiler's own check: a compiler bug, never a frame error.
    SelfCheck,
}

/// The variant name, such as `BadValue`.
impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// A compile error with its source: file, dotted key path and layer when known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The failure class.
    pub code: Code,
    /// The file the offending key came from, when known.
    pub file: Option<PathBuf>,
    /// The dotted key path, such as `worker.sshd.restart.policy`; empty when the error is not
    /// about one key (a whole file, or a database-wide limit).
    pub key: String,
    /// The layer the offending key came from, when known.
    pub layer: Option<String>,
    /// What is wrong, for a human.
    pub detail: String,
}

/// `<file>: <key> [<layer>]: <code>: <detail>`, leaving out the parts that are absent.
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(file) = &self.file {
            write!(f, "{}: ", file.display())?;
        }
        match (self.key.is_empty(), &self.layer) {
            (false, Some(l)) => write!(f, "{} [{l}]: ", self.key)?,
            (false, None) => write!(f, "{}: ", self.key)?,
            (true, Some(l)) => write!(f, "[{l}]: ")?,
            (true, None) => {}
        }
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Error {}

impl Error {
    /// An error with a key and detail and no file or layer.
    #[must_use]
    pub fn new(code: Code, key: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            file: None,
            key: key.into(),
            layer: None,
            detail: detail.into(),
        }
    }

    /// Attach the file the error came from.
    #[must_use]
    pub fn in_file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Attach the layer the error came from.
    #[must_use]
    pub fn in_layer(mut self, layer: impl Into<String>) -> Self {
        self.layer = Some(layer.into());
        self
    }
}

/// A non-fatal finding, such as a dropped optional dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// The dotted key path the warning is about.
    pub key: String,
    /// What was found, for a human.
    pub detail: String,
}
