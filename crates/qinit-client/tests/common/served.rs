// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! A colony on a thread behind a real socket, shared by the client tests and the C interface's
//! smoke test.
#![allow(dead_code)] // each test binary uses a different part of the harness

#[path = "../../../qinit-colony/tests/common/mod.rs"]
pub mod common;

use common::{boot, boot_with_policy};
use qinit_client::Client;
use qinit_colony::sim::{Script, Sim, advance_outcome};
use qinit_colony::{Colony, Peer};
use qinit_ipc::listen_seqpacket;
use qinit_proto::Limits;
use qinit_proto::testing::Driver;
use std::ffi::CString;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::thread::JoinHandle;

pub fn frames() -> String {
    "[worker.db]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/db\"]\n\
     [worker.app]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/app\"]\n\
     deps = [{ group = \"require_all\", edges = [{ to = \"db\" }] }]\n\
     [forager.backup]\ncredentials = { uid = \"svc\" }\nexec = [\"/bin/backup\"]\n\
     [forager.backup.launch]\nconcurrency = 2\nargv_tail = 2\nenv = [\"TARGET\"]\nfds = [\"stdout\"]\n"
        .to_owned()
}

/// A server on a thread, until dropped.
pub struct Served {
    pub path: PathBuf,
    stop: Option<OwnedFd>,
    thread: Option<JoinHandle<Colony<Sim>>>,
    _dir: PathBuf,
}

impl Served {
    pub fn start(enable: &[&str], root: bool, instance: Script) -> Served {
        Served::start_with(enable, root, instance, Vec::new())
    }

    /// As [`Served::start`], with the pidfds the simulated effects hand out.
    pub fn start_with(
        enable: &[&str],
        root: bool,
        instance: Script,
        pidfds: Vec<OwnedFd>,
    ) -> Served {
        Served::start_policy(enable, root, instance, pidfds, None)
    }

    /// As [`Served::start_with`], with a compiled policy when `policy` is given.
    pub fn start_policy(
        enable: &[&str],
        root: bool,
        instance: Script,
        pidfds: Vec<OwnedFd>,
        policy: Option<&str>,
    ) -> Served {
        let dir = std::env::temp_dir().join(format!(
            "qinit-client-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "-")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("colony");
        let c = CString::new(path.to_str().unwrap()).unwrap();
        let listener = listen_seqpacket(&c, 16).unwrap();
        let mut colony = match policy {
            Some(p) => boot_with_policy(&frames(), enable, p, Sim::new()),
            None => boot(&frames(), enable, Sim::new()).0,
        };
        colony.effects.instance_script = instance;
        colony.effects.pidfds.extend(pidfds);
        let mut driver = Driver::new(listener, Limits::default()).unwrap();
        if root {
            driver.identity = Some(Peer {
                uid: 0,
                gid: 0,
                pid: 1,
            });
        }
        let (stop_r, stop_w) = qinit_sys::fd::pipe(0o2_000_000).unwrap();
        let thread = std::thread::spawn(move || {
            driver
                .serve_until(&mut colony, stop_r.as_fd(), |c| {
                    let out = advance_outcome(c, 0);
                    (c.effects.now(), out)
                })
                .unwrap();
            colony
        });
        Served {
            path,
            stop: Some(stop_w),
            thread: Some(thread),
            _dir: dir,
        }
    }

    pub fn client(&self) -> Client {
        Client::connect(&self.path).unwrap()
    }

    pub fn finish(mut self) -> Colony<Sim> {
        drop(self.stop.take());
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn instant(exit: Option<i32>) -> Script {
    Script {
        ready_after_ms: None,
        exit_after: exit.map(|s| (0, Some(s))),
        ..Script::default()
    }
}
