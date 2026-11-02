// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Stable error codes and the error and warning records of the frame compiler.
use std::path::PathBuf;

/// Stable error code; one per failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Io,
    Parse,
    UnknownKey,
    DuplicateFrame,
    BadValue,
    ListOp,
    BadName,
    MissingTarget,
    DuplicateName,
    Template,
    Instance,
    Policy,
    Limit,
    Cycle,
    HardParallel,
    SelfCheck,
}

/// A compile error with its source: file, dotted key path and layer when known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub file: Option<PathBuf>,
    pub key: String,
    pub layer: Option<String>,
    pub detail: String,
}

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
    pub key: String,
    pub detail: String,
}
