// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Colony's own memory across a restart: three files in `<run>/state` (see `docs/colony.md`).
//! They are not configuration. A line that does not parse refuses its whole file, and colony
//! carries on as if the file were absent.
//!
//! `cells`: `<name> <cgroup id> <ready 0|1> <main pid> <main start time>`.
//! `nodes`: `<name> <wanted 0|1> <off|done|quarantined:<reason>> <burst_begin_ms> <burst_count>
//! <backoff_exp> <last_start_ms> <ended_ms>`.
//! `colony.db`: the database colony runs, verbatim.
use qinit_colony::{Counters, Reason, SavedTerminal};
use qinit_sys::Errno;
use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// A cell colony has created and not yet removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellLine {
    pub name: String,
    pub cgroup_id: u64,
    pub ready: bool,
    /// The main process's pid, 0 for none.
    pub pid: i32,
    /// Field 22 of `/proc/<pid>/stat`, 0 with no main.
    pub start_time: u64,
}

/// A node that is not plain off and unwanted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeLine {
    pub name: String,
    pub wanted: bool,
    pub terminal: Option<SavedTerminal>,
    pub counters: Counters,
}

/// The state directory.
#[derive(Debug)]
pub struct State {
    dir: PathBuf,
}

fn errno(e: &std::io::Error) -> Errno {
    Errno(e.raw_os_error().unwrap_or(libc::EIO))
}

fn reason_word(r: Reason) -> &'static str {
    match r {
        Reason::Breaker => "breaker",
        Reason::Cascade => "cascade",
        Reason::StartTimeout => "start_timeout",
        Reason::StopFailed => "stop_failed",
    }
}

fn reason_of(word: &str) -> Option<Reason> {
    Some(match word {
        "breaker" => Reason::Breaker,
        "cascade" => Reason::Cascade,
        "start_timeout" => Reason::StartTimeout,
        "stop_failed" => Reason::StopFailed,
        _ => return None,
    })
}

fn flag(word: &str) -> Option<bool> {
    match word {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn parse_cell(text: &str) -> Option<CellLine> {
    let f: Vec<&str> = text.split_whitespace().collect();
    let [name, id, ready, pid, start] = f[..] else {
        return None;
    };
    Some(CellLine {
        name: name.to_owned(),
        cgroup_id: id.parse().ok()?,
        ready: flag(ready)?,
        pid: pid.parse().ok()?,
        start_time: start.parse().ok()?,
    })
}

fn parse_node(text: &str) -> Option<NodeLine> {
    let f: Vec<&str> = text.split_whitespace().collect();
    let [name, wanted, end, begin, count, exp, last, ended] = f[..] else {
        return None;
    };
    let terminal = match end {
        "off" => None,
        "done" => Some(SavedTerminal::Done),
        _ => Some(SavedTerminal::Quarantined(reason_of(
            end.strip_prefix("quarantined:")?,
        )?)),
    };
    Some(NodeLine {
        name: name.to_owned(),
        wanted: flag(wanted)?,
        terminal,
        counters: Counters {
            burst_begin_ms: begin.parse().ok()?,
            burst_count: count.parse().ok()?,
            backoff_exp: exp.parse().ok()?,
            last_start_ms: last.parse().ok()?,
            ended_ms: ended.parse().ok()?,
        },
    })
}

impl State {
    /// Opens `<run>/state`, making it (mode 0700) if it is not there. A `state` that is a symlink,
    /// is not a directory or belongs to someone else is refused: its contents would steer
    /// what colony adopts.
    ///
    /// # Errors
    ///
    /// `ELOOP` for a symlink, `ENOTDIR` for a file, `EPERM` for another owner, else the errno
    /// of the file system.
    pub fn open(run: &Path) -> Result<State, Errno> {
        let dir = run.join("state");
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_symlink() => return Err(Errno(libc::ELOOP)),
            Ok(m) if !m.is_dir() => return Err(Errno(libc::ENOTDIR)),
            Ok(m) if m.uid() != qinit_sys::cred::getuid() => return Err(Errno(libc::EPERM)),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&dir)
                    .map_err(|e| errno(&e))?;
            }
            Err(e) => return Err(errno(&e)),
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| errno(&e))?;
        Ok(State { dir })
    }

    /// Writes `bytes` whole to a temporary file (0600) and renames it over `name`, so a reader
    /// sees the old file or the new one, never half of either.
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), Errno> {
        let tmp = self.dir.join(format!(".{name}.tmp"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| errno(&e))?;
        // A leftover from a crash may have another mode: make it ours.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| errno(&e))?;
        f.write_all(bytes).map_err(|e| errno(&e))?;
        drop(f);
        std::fs::rename(&tmp, self.dir.join(name)).map_err(|e| errno(&e))
    }

    /// Rewrites the `cells` file.
    ///
    /// # Errors
    ///
    /// The errno of writing or renaming.
    pub fn write_cells(&self, cells: &[CellLine]) -> Result<(), Errno> {
        let mut text = String::new();
        for c in cells {
            let _ = writeln!(
                text,
                "{} {} {} {} {}",
                c.name,
                c.cgroup_id,
                u8::from(c.ready),
                c.pid,
                c.start_time
            );
        }
        self.write("cells", text.as_bytes())
    }

    /// Rewrites the `nodes` file.
    ///
    /// # Errors
    ///
    /// The errno of writing or renaming.
    pub fn write_nodes(&self, nodes: &[NodeLine]) -> Result<(), Errno> {
        let mut text = String::new();
        for n in nodes {
            let end = match n.terminal {
                None => "off".to_owned(),
                Some(SavedTerminal::Done) => "done".to_owned(),
                Some(SavedTerminal::Quarantined(r)) => format!("quarantined:{}", reason_word(r)),
            };
            let c = n.counters;
            let _ = writeln!(
                text,
                "{} {} {end} {} {} {} {} {}",
                n.name,
                u8::from(n.wanted),
                c.burst_begin_ms,
                c.burst_count,
                c.backoff_exp,
                c.last_start_ms,
                c.ended_ms
            );
        }
        self.write("nodes", text.as_bytes())
    }

    /// Rewrites the `colony.db` copy.
    ///
    /// # Errors
    ///
    /// The errno of writing or renaming.
    pub fn write_db(&self, bytes: &[u8]) -> Result<(), Errno> {
        self.write("colony.db", bytes)
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(self.dir.join(name)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{name}: {e}")),
        }
    }

    fn read_lines<T>(
        &self,
        name: &str,
        parse: fn(&str) -> Option<T>,
    ) -> Result<Option<Vec<T>>, String> {
        let Some(bytes) = self.read(name)? else {
            return Ok(None);
        };
        let text = String::from_utf8(bytes).map_err(|_| format!("{name}: not text"))?;
        let mut out = Vec::new();
        for (i, l) in text.lines().enumerate() {
            if l.trim().is_empty() {
                continue;
            }
            out.push(parse(l).ok_or_else(|| format!("{name}: line {} is malformed", i + 1))?);
        }
        Ok(Some(out))
    }

    /// The `cells` file; `None` when absent.
    ///
    /// # Errors
    ///
    /// Text naming the file and the first malformed line.
    pub fn read_cells(&self) -> Result<Option<Vec<CellLine>>, String> {
        self.read_lines("cells", parse_cell)
    }

    /// The `nodes` file; `None` when absent.
    ///
    /// # Errors
    ///
    /// Text naming the file and the first malformed line.
    pub fn read_nodes(&self) -> Result<Option<Vec<NodeLine>>, String> {
        self.read_lines("nodes", parse_node)
    }

    /// The `colony.db` copy; `None` when absent.
    ///
    /// # Errors
    ///
    /// Text naming the file when it cannot be read.
    pub fn read_db(&self) -> Result<Option<Vec<u8>>, String> {
        self.read("colony.db")
    }

    /// Removes the three files (a clean start has nothing to adopt).
    pub fn clear(&self) {
        for f in ["cells", "nodes", "colony.db"] {
            let _ = std::fs::remove_file(self.dir.join(f));
        }
    }
}
