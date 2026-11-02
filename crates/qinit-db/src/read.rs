// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The reader: length and CRC, then the proved validator; `decode` is total afterwards.

use crate::crc::file_crc;
use crate::model::{
    Cred, Edge, Group, GroupKind, Kind, Mode, Model, Node, Ready, Restart, RestartOn,
    RestartPolicy, Route, Seccomp, Securebits, Target,
};
use qinit_db_core::{
    DbError, H_CRC32, HEADER_WORDS, MAX_EDGES, MAX_NODES, NONE, T_CREDS, T_EDGES, T_ENABLED,
    T_GROUPS, T_NODES, T_POOL, T_PRESYSLOG, T_ROUTES, WORDS, validate, word,
};
use qinit_graph_core::GEdge;

/// Why a database is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The CRC does not match.
    Crc,
    /// The validator refused it.
    Db(DbError),
}

/// A validated database. Only [`open`] makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reader<'a> {
    bytes: &'a [u8],
}

/// Checks the length and CRC of `bytes`, then validates them.
///
/// # Errors
/// [`ReadError::Crc`] on a CRC mismatch, [`ReadError::Db`] with the validator's verdict.
pub fn open(bytes: &[u8]) -> Result<Reader<'_>, ReadError> {
    if bytes.len() < 4 * HEADER_WORDS {
        return Err(ReadError::Db(DbError::Header));
    }
    if word(bytes, H_CRC32) != file_crc(bytes) {
        return Err(ReadError::Crc);
    }
    let mut edges = vec![
        GEdge {
            from: 0,
            to: 0,
            hard: false,
            parallel: false
        };
        MAX_EDGES
    ];
    let mut levels = vec![0u32; MAX_NODES];
    validate(bytes, &mut edges, &mut levels).map_err(ReadError::Db)?;
    Ok(Reader { bytes })
}

impl Reader<'_> {
    fn header(&self, i: usize) -> u32 {
        word(self.bytes, i)
    }

    fn count(&self, t: usize) -> usize {
        self.header(5 + 2 * t) as usize
    }

    /// Word `w` of record `r` of table `t` (`t < 7`).
    fn field(&self, t: usize, r: usize, w: usize) -> u32 {
        word(
            self.bytes,
            self.header(4 + 2 * t) as usize / 4 + r * WORDS[t] + w,
        )
    }

    fn string(&self, off: u32, len: u32) -> &str {
        let start = self.header(4 + 2 * T_POOL) as usize + off as usize;
        let raw = &self.bytes[start..start + len as usize];
        core::str::from_utf8(raw).expect("validated by qinit-db-core")
    }

    fn list(&self, off: u32, len: u32) -> Vec<String> {
        if len == 0 {
            return Vec::new();
        }
        self.string(off, len)
            .split('\0')
            .map(str::to_owned)
            .collect()
    }

    fn opt(v: u32) -> Option<u32> {
        (v != NONE).then_some(v)
    }

    /// The model this database encodes. Total after a successful [`open`].
    #[must_use]
    pub fn decode(&self) -> Model {
        Model {
            nodes: (0..self.count(T_NODES)).map(|i| self.node(i)).collect(),
            creds: (0..self.count(T_CREDS)).map(|c| self.cred(c)).collect(),
            routes: (0..self.count(T_ROUTES)).map(|r| self.route(r)).collect(),
            enabled: (0..self.count(T_ENABLED))
                .map(|k| self.field(T_ENABLED, k, 0))
                .collect(),
            presyslog: (0..self.count(T_PRESYSLOG))
                .map(|k| self.field(T_PRESYSLOG, k, 0))
                .collect(),
        }
    }

    fn node(&self, i: usize) -> Node {
        let f = |w| self.field(T_NODES, i, w);
        let ready_arg = || self.string(f(6), f(7)).to_owned();
        let first = f(14) as usize;
        let instance = self.string(f(18), f(19));
        Node {
            kind: match f(0) {
                0 => Kind::Worker,
                1 => Kind::Forager,
                _ => Kind::Brood,
            },
            name: self.string(f(1), f(2)).to_owned(),
            exec: self.list(f(3), f(4)),
            ready: match f(5) {
                0 => Ready::Pipe,
                1 => Ready::Exit,
                2 => Ready::Socket(ready_arg()),
                _ => Ready::Path(ready_arg()),
            },
            restart: Restart {
                policy: match f(8) {
                    0 => RestartPolicy::Never,
                    1 => RestartPolicy::OnFailure,
                    _ => RestartPolicy::Always,
                },
                max: f(9),
                window_ms: f(10),
            },
            output: Self::opt(f(11)),
            errors: Self::opt(f(12)),
            cred: Self::opt(f(13)),
            groups: (first..first + f(15) as usize)
                .map(|g| self.group(g))
                .collect(),
            memory_max_kib: f(16),
            pids_max: f(17),
            instance_of: (!instance.is_empty()).then(|| instance.to_owned()),
        }
    }

    fn group(&self, g: usize) -> Group {
        let first = self.field(T_GROUPS, g, 1) as usize;
        Group {
            kind: match self.field(T_GROUPS, g, 0) {
                0 => GroupKind::RequireAll,
                1 => GroupKind::RequireAny,
                2 => GroupKind::OptionalAll,
                _ => GroupKind::ExcludeAll,
            },
            edges: (first..first + self.field(T_GROUPS, g, 2) as usize)
                .map(|x| self.edge(x))
                .collect(),
        }
    }

    fn edge(&self, x: usize) -> Edge {
        let f = |w| self.field(T_EDGES, x, w);
        Edge {
            target: if f(0) == 0 {
                Target::Node(f(1))
            } else {
                Target::Path(self.string(f(1), f(2)).to_owned())
            },
            mode: if f(3) == 0 { Mode::Sync } else { Mode::Async },
            deadline_ms: f(4),
            restart_on: match f(5) {
                0 => RestartOn::None,
                1 => RestartOn::Error,
                2 => RestartOn::Restart,
                _ => RestartOn::Refresh,
            },
            stop_parallel: f(6) & 1 == 1,
        }
    }

    fn cred(&self, c: usize) -> Cred {
        let f = |w| self.field(T_CREDS, c, w);
        Cred {
            user: self.string(f(0), f(1)).to_owned(),
            caps: u64::from(f(2)) | (u64::from(f(3)) << 32),
            securebits: match f(4) {
                0 => Securebits::None,
                1 => Securebits::Noroot,
                _ => Securebits::NorootLocked,
            },
            nnp: f(5) != 0,
            ns: f(6),
            seccomp: if f(7) == 0 {
                Seccomp::None
            } else {
                Seccomp::Default
            },
            landlock: self.list(f(8), f(9)),
        }
    }

    fn route(&self, r: usize) -> Route {
        let f = |w| self.field(T_ROUTES, r, w);
        if f(0) == 0 {
            Route::Path(self.string(f(1), f(2)).to_owned())
        } else {
            Route::Pipe(f(1))
        }
    }
}
