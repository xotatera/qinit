// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which files are shell scripts: the `shellcheck` gate's input set.

/// A `.sh` file, or any file whose first line is a `sh` or `bash` shebang
/// (the git hook templates have no extension).
#[must_use]
pub fn is_shell_script(path: &str, first_line: &str) -> bool {
    if std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e == "sh")
    {
        return true;
    }
    let Some(rest) = first_line.strip_prefix("#!") else {
        return false;
    };
    let mut words = rest.split_whitespace();
    let interpreter = match words.next() {
        Some(p) if p.ends_with("/env") => words.next(),
        other => other,
    };
    interpreter
        .and_then(|p| p.rsplit('/').next())
        .is_some_and(|name| name == "sh" || name == "bash")
}
