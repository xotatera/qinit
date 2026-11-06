// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! One watcher for the three uses of a path: a dependency edge (*exists*) and a node's readiness
//! as a path or a socket (*created after the start*). See `docs/colony.md`.
//!
//! A path may not exist yet, nor its directories. The watcher keeps an inotify watch on the
//! nearest existing directory above the final component, for creates and moves into it. When the
//! next component appears it moves one level down; when a watched directory is removed or moved
//! it climbs back. Every watch is set before the check it protects, so a path made in between
//! is seen by the check or by the event, and at most once.
use qinit_event::{Loop, Token};
use qinit_sys::Errno;
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::os::unix::fs::FileTypeExt;
use std::path::{Component, Path, PathBuf};

const MASK: u32 = libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;
const APPEARS: u32 = libc::IN_CREATE | libc::IN_MOVED_TO;
const GOES: u32 = libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;

/// What satisfies a watched path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    /// The path exists (as `stat` sees it), now or later.
    Exists,
    /// An entry is created or moved into place at the path after the watch began. What was
    /// there at the start does not count.
    Created,
    /// As `Created`, and the new entry is a socket.
    CreatedSocket,
}

struct Entry {
    /// The components of the absolute path.
    names: Vec<OsString>,
    want: Want,
    /// The watch descriptor on the directory `depth` components down, once placed.
    wd: Option<i32>,
    depth: usize,
}

/// The watched paths, by the caller's ids, over one inotify set of a [`Loop`].
pub struct Watcher {
    token: Token,
    entries: BTreeMap<u64, Entry>,
    /// The entries on each watch descriptor: directories are shared.
    wds: HashMap<i32, Vec<u64>>,
    errors: Vec<(u64, Errno)>,
    /// Runs after a watch is set and before the existence check that follows it. A hook for
    /// tests that make the path in exactly that window.
    #[cfg(feature = "testing")]
    pub between: Option<Box<dyn FnMut()>>,
}

fn prefix(names: &[OsString], n: usize) -> PathBuf {
    let mut p = PathBuf::from("/");
    p.extend(&names[..n]);
    p
}

fn is_dir(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_dir())
}

fn is_socket(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_socket())
}

fn split(path: &Path) -> Result<Vec<OsString>, Errno> {
    let mut names = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(n) => names.push(n.to_owned()),
            Component::ParentDir | Component::Prefix(_) => return Err(Errno(libc::EINVAL)),
        }
    }
    if !path.is_absolute() || names.is_empty() {
        return Err(Errno(libc::EINVAL));
    }
    Ok(names)
}

impl Watcher {
    /// A watcher with its inotify set registered in `l` under `token`.
    ///
    /// # Errors
    ///
    /// The errno of creating or registering the inotify instance.
    pub fn new(l: &mut Loop, token: Token) -> Result<Watcher, Errno> {
        l.add_inotify_set(token).map_err(Errno::from)?;
        Ok(Watcher {
            token,
            entries: BTreeMap::new(),
            wds: HashMap::new(),
            errors: Vec::new(),
            #[cfg(feature = "testing")]
            between: None,
        })
    }

    /// The inotify token the loop reports this watcher's events under.
    #[must_use]
    pub fn token(&self) -> Token {
        self.token
    }

    /// How many paths are still being waited for.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.entries.len()
    }

    /// Starts waiting for `path` under `id` (an earlier entry with the same id is replaced).
    /// For `Exists`, `Ok(true)` means it exists now and nothing is kept. For the two `Created`
    /// kinds the state now never counts, so the answer is always `Ok(false)`.
    ///
    /// # Errors
    ///
    /// `EINVAL` for a path that is not absolute or has a `..`; otherwise the errno of the watch.
    pub fn add(&mut self, l: &mut Loop, id: u64, path: &Path, want: Want) -> Result<bool, Errno> {
        self.remove(l, id);
        let names = split(path)?;
        self.entries.insert(
            id,
            Entry {
                names,
                want,
                wd: None,
                depth: 0,
            },
        );
        match self.place(l, id, true) {
            Ok(true) => {
                self.remove(l, id);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(e) => {
                self.remove(l, id);
                Err(e)
            }
        }
    }

    /// Stops waiting for `id`; its directory watch ends with its last user.
    pub fn remove(&mut self, l: &mut Loop, id: u64) {
        if let Some(e) = self.entries.remove(&id)
            && let Some(wd) = e.wd
        {
            self.detach(l, id, wd);
        }
    }

    fn detach(&mut self, l: &mut Loop, id: u64, wd: i32) {
        let Some(ids) = self.wds.get_mut(&wd) else {
            return;
        };
        ids.retain(|&i| i != id);
        if ids.is_empty() {
            self.wds.remove(&wd);
            // The kernel already dropped the watch of a directory that was deleted.
            let _ = l.unwatch(self.token, wd);
        }
    }

    /// The ids were renumbered: each entry's id goes through `renumber`, and an entry it maps to
    /// `None` is dropped.
    pub fn remap(&mut self, l: &mut Loop, renumber: impl Fn(u64) -> Option<u64>) {
        let old: Vec<u64> = self.entries.keys().copied().collect();
        let mut moved = Vec::new();
        for id in old {
            match renumber(id) {
                Some(new) if new == id => {}
                Some(new) => moved.push((id, new)),
                None => self.remove(l, id),
            }
        }
        // Two passes so that ids that swap places do not overwrite each other.
        let taken: Vec<(u64, u64, Entry)> = moved
            .into_iter()
            .filter_map(|(id, new)| self.entries.remove(&id).map(|e| (id, new, e)))
            .collect();
        for (id, new, e) in taken {
            if let Some(wd) = e.wd
                && let Some(ids) = self.wds.get_mut(&wd)
            {
                ids.retain(|&i| i != id);
                ids.push(new);
            }
            self.entries.insert(new, e);
        }
    }

    /// Paths whose watch could not be moved (the kernel refused), with the errno, since the
    /// last call. Such a path is not watched any more.
    pub fn take_errors(&mut self) -> Vec<(u64, Errno)> {
        std::mem::take(&mut self.errors)
    }

    /// Puts `id`'s watch on the deepest existing directory above its final component, then
    /// checks the path. `initial`: the state of the path now is the state at the start.
    fn place(&mut self, l: &mut Loop, id: u64, initial: bool) -> Result<bool, Errno> {
        let Some(e) = self.entries.get(&id) else {
            return Ok(false);
        };
        let (names, want, old) = (e.names.clone(), e.want, e.wd);
        let len = names.len();
        let depth = (0..len)
            .rev()
            .find(|&n| is_dir(&prefix(&names, n)))
            .unwrap_or(0);
        let wd = l
            .watch(self.token, &prefix(&names, depth), MASK)
            .map_err(Errno::from)?;
        if old != Some(wd) {
            if let Some(old) = old {
                self.detach(l, id, old);
            }
            self.wds.entry(wd).or_default().push(id);
        }
        if let Some(e) = self.entries.get_mut(&id) {
            e.wd = Some(wd);
            e.depth = depth;
        }
        #[cfg(feature = "testing")]
        if let Some(hook) = self.between.as_mut() {
            hook();
        }
        let full = prefix(&names, len);
        Ok(match want {
            Want::Exists => std::fs::metadata(&full).is_ok(),
            Want::Created => !initial && std::fs::symlink_metadata(&full).is_ok(),
            Want::CreatedSocket => !initial && is_socket(&full),
        })
    }

    /// Handles the events of the inotify set: `(watch descriptor, mask, name)`. Returns the ids
    /// now satisfied; each is reported once and then forgotten.
    pub fn on_events(&mut self, l: &mut Loop, evs: &[(i32, u32, OsString)]) -> Vec<u64> {
        let mut done = Vec::new();
        for (wd, mask, name) in evs {
            let ids = self.wds.get(wd).cloned().unwrap_or_default();
            for id in ids {
                let Some(e) = self.entries.get(&id) else {
                    continue;
                };
                if e.wd != Some(*wd) {
                    continue;
                }
                let appears = mask & APPEARS != 0 && e.names.get(e.depth) == Some(name);
                if mask & GOES == 0 && !appears {
                    continue;
                }
                let last = appears && e.depth + 1 == e.names.len();
                let satisfied = if last && e.want == Want::Created {
                    // The event itself is what counts.
                    Ok(true)
                } else if last && e.want == Want::CreatedSocket {
                    Ok(is_socket(&prefix(&e.names, e.names.len())))
                } else {
                    self.place(l, id, false)
                };
                match satisfied {
                    Ok(true) => {
                        self.remove(l, id);
                        done.push(id);
                    }
                    Ok(false) => {}
                    Err(errno) => {
                        self.remove(l, id);
                        self.errors.push((id, errno));
                    }
                }
            }
        }
        done
    }
}
