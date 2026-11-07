// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Colony's own memory across a restart, as text. Queen holds it (`docs/queen.md`): the `cells`
//! entry has one line per cell, `<name> <cgroup id> <ready 0|1> <dir key> <main key>`; the `nodes`
//! entry has one line per node, `<name> <wanted 0|1> <off|done|quarantined:<reason>>
//! <burst_begin_ms> <burst_count> <backoff_exp> <last_start_ms> <ended_ms>`, and one `pipe
//! <logger> <read key> <write key>` line per logger pipe. A line that does not parse refuses its
//! whole entry, and colony carries on as if the entry were absent.
use crate::store::{KEY_CELLS, KEY_DB, KEY_NODES};
use qinit_colony::{Counters, Reason, SavedTerminal};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// A cell colony has created and not yet removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellLine {
    pub name: String,
    pub cgroup_id: u64,
    pub ready: bool,
    /// The store key of the cell's directory descriptor.
    pub dir_key: u64,
    /// The store key of the main process's pidfd, 0 for none.
    pub main_key: u64,
}

/// A logger pipe queen holds both ends of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeLine {
    /// The logger node's name.
    pub logger: String,
    pub read: u64,
    pub write: u64,
}

/// A node that is not plain off and unwanted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeLine {
    pub name: String,
    pub wanted: bool,
    pub terminal: Option<SavedTerminal>,
    pub counters: Counters,
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

/// A store key a cell or pipe is held under: a number, and not one of the three that hold the
/// state itself (0 is no key; callers that allow it say so).
fn key(word: &str) -> Option<u64> {
    word.parse()
        .ok()
        .filter(|k| ![KEY_CELLS, KEY_NODES, KEY_DB].contains(k))
}

/// Whether every key in `keys` that is not 0 is there once, else the first that is not.
fn once(keys: impl IntoIterator<Item = u64>) -> Result<(), u64> {
    let mut seen = BTreeSet::new();
    for k in keys.into_iter().filter(|k| *k != 0) {
        if !seen.insert(k) {
            return Err(k);
        }
    }
    Ok(())
}

fn parse_cell(text: &str) -> Option<CellLine> {
    let f: Vec<&str> = text.split_whitespace().collect();
    let [name, id, ready, dir, main] = f[..] else {
        return None;
    };
    Some(CellLine {
        name: name.to_owned(),
        cgroup_id: id.parse().ok()?,
        ready: flag(ready)?,
        dir_key: key(dir).filter(|k| *k != 0)?,
        main_key: key(main)?,
    })
}

fn parse_pipe(f: &[&str]) -> Option<PipeLine> {
    let [_, logger, read, write] = f[..] else {
        return None;
    };
    Some(PipeLine {
        logger: logger.to_owned(),
        read: key(read).filter(|k| *k != 0)?,
        write: key(write).filter(|k| *k != 0)?,
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

/// The text of the `cells` entry.
#[must_use]
pub fn format_cells(cells: &[CellLine]) -> String {
    let mut text = String::new();
    for c in cells {
        let _ = writeln!(
            text,
            "{} {} {} {} {}",
            c.name,
            c.cgroup_id,
            u8::from(c.ready),
            c.dir_key,
            c.main_key
        );
    }
    text
}

/// The text of the `nodes` entry: the nodes, then the logger pipes.
#[must_use]
pub fn format_nodes(nodes: &[NodeLine], pipes: &[PipeLine]) -> String {
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
    for p in pipes {
        let _ = writeln!(text, "pipe {} {} {}", p.logger, p.read, p.write);
    }
    text
}

fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
}

/// The cells in `text`.
///
/// # Errors
///
/// Text naming the first malformed line.
pub fn parse_cells(text: &str) -> Result<Vec<CellLine>, String> {
    let cells: Vec<CellLine> = lines(text)
        .map(|(i, l)| parse_cell(l).ok_or_else(|| format!("cells: line {} is malformed", i + 1)))
        .collect::<Result<_, _>>()?;
    once(cells.iter().flat_map(|c| [c.dir_key, c.main_key]))
        .map_err(|k| format!("cells: key {k} is named twice"))?;
    Ok(cells)
}

/// Whether no key is named by both a cell and a pipe.
///
/// # Errors
///
/// Text naming the first key that two descriptors would be taken from.
pub fn check_disjoint(cells: &[CellLine], pipes: &[PipeLine]) -> Result<(), String> {
    once(
        cells
            .iter()
            .flat_map(|c| [c.dir_key, c.main_key])
            .chain(pipes.iter().flat_map(|p| [p.read, p.write])),
    )
    .map_err(|k| format!("key {k} is named twice, by a cell and a pipe"))
}

/// The nodes and logger pipes in `text`. A `pipe` line is told from a node named `pipe` by its
/// four fields (a node line has eight).
///
/// # Errors
///
/// Text naming the first malformed line.
pub fn parse_nodes(text: &str) -> Result<(Vec<NodeLine>, Vec<PipeLine>), String> {
    let (mut nodes, mut pipes) = (Vec::new(), Vec::new());
    for (i, l) in lines(text) {
        let f: Vec<&str> = l.split_whitespace().collect();
        let bad = || format!("nodes: line {} is malformed", i + 1);
        if f.first() == Some(&"pipe") && f.len() == 4 {
            pipes.push(parse_pipe(&f).ok_or_else(bad)?);
        } else {
            nodes.push(parse_node(l).ok_or_else(bad)?);
        }
    }
    once(pipes.iter().flat_map(|p| [p.read, p.write]))
        .map_err(|k| format!("nodes: key {k} is named twice"))?;
    Ok((nodes, pipes))
}
