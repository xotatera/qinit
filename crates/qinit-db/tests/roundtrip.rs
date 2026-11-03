// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
mod common;

use common::{node, sample, svc};
use qinit_db::{
    Kind, Model, ReadError, Seccomp, Stop, StopMode, Target, WriteError, crc32, open, write,
};
use qinit_db_core::{T_POOL, word};

#[test]
fn a_model_round_trips_through_write_open_decode() {
    let model = sample();
    let bytes = write(&model).expect("writes");
    let reader = open(&bytes).expect("opens");
    assert_eq!(reader.decode(), model);
}

#[test]
fn equal_models_write_byte_identical_databases() {
    assert_eq!(write(&sample()).unwrap(), write(&sample()).unwrap());
}

#[test]
fn the_writer_interns_equal_strings_once() {
    let mut model = Model::default();
    for name in ["a", "b", "c"] {
        let mut n = node(name, Kind::Worker);
        n.exec = vec!["/usr/bin/same".into(), "-x".into()];
        model.nodes.push(n);
    }
    model.creds.push(svc());
    let bytes = write(&model).unwrap();
    let pool_len = word(&bytes, 5 + 2 * T_POOL) as usize;
    let sum: usize = "/usr/bin/same\0-x".len() * 3 + 3;
    assert!(pool_len < sum, "pool {pool_len} vs {sum}");
    assert_eq!(
        pool_len,
        "/usr/bin/same\0-x".len() + 3 + "/".len() + "svc".len()
    );
    assert_eq!(open(&bytes).unwrap().decode(), model);
}

#[test]
fn the_writer_refuses_unsorted_nodes() {
    let model = Model {
        nodes: vec![node("b", Kind::Worker), node("a", Kind::Worker)],
        ..Model::default()
    };
    assert_eq!(write(&model), Err(WriteError::Unsorted));
    let dup = Model {
        nodes: vec![node("a", Kind::Worker), node("a", Kind::Worker)],
        ..Model::default()
    };
    assert_eq!(write(&dup), Err(WriteError::Unsorted));
}

#[test]
fn the_writer_refuses_a_limit_overflow() {
    let model = Model {
        nodes: (0..4097)
            .map(|i| node(&format!("n{i:05}"), Kind::Worker))
            .collect(),
        ..Model::default()
    };
    assert_eq!(write(&model), Err(WriteError::Limit("nodes")));
}

#[test]
fn the_writer_refuses_a_dangling_index() {
    let mut model = Model {
        nodes: vec![node("a", Kind::Worker)],
        ..Model::default()
    };
    model.nodes[0].groups = vec![qinit_db::Group {
        kind: qinit_db::GroupKind::RequireAll,
        edges: vec![common::edge(Target::Node(9), qinit_db::Mode::Sync, 0)],
    }];
    assert_eq!(write(&model), Err(WriteError::Index));
}

fn with_node(f: impl FnOnce(&mut qinit_db::Node)) -> Model {
    let mut n = node("a", Kind::Worker);
    f(&mut n);
    Model {
        nodes: vec![n],
        creds: vec![svc()],
        ..Model::default()
    }
}

fn with_landlock(entries: &[&str]) -> Model {
    let mut m = Model::default();
    m.creds.push(sample().creds.remove(0));
    m.creds[0].landlock = entries.iter().map(|s| (*s).to_owned()).collect();
    m
}

#[test]
fn the_writer_refuses_an_empty_exec_element() {
    let m = with_node(|n| n.exec = vec![String::new()]);
    assert_eq!(write(&m), Err(WriteError::Limit("empty list element")));
}

#[test]
fn the_writer_refuses_an_empty_landlock_element() {
    let m = with_landlock(&["ro:/a", ""]);
    assert_eq!(write(&m), Err(WriteError::Limit("empty list element")));
}

#[test]
fn the_writer_refuses_a_nul_in_an_exec_element() {
    let m = with_node(|n| n.exec = vec!["a\0b".into()]);
    assert_eq!(write(&m), Err(WriteError::Limit("nul in list element")));
}

#[test]
fn the_writer_refuses_a_nul_in_a_landlock_element() {
    let m = with_landlock(&["ro:/a\0b"]);
    assert_eq!(write(&m), Err(WriteError::Limit("nul in list element")));
}

#[test]
fn the_writer_refuses_an_empty_instance_of() {
    let m = with_node(|n| n.instance_of = Some(String::new()));
    assert_eq!(write(&m), Err(WriteError::Limit("empty instance_of")));
}

#[test]
fn crc32_matches_the_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn the_empty_model_is_a_valid_database() {
    let bytes = write(&Model::default()).unwrap();
    let reader = open(&bytes).expect("opens");
    assert_eq!(reader.decode(), Model::default());
    assert!(matches!(open(&bytes[..10]), Err(ReadError::Db(_))));
}

#[test]
fn the_new_fields_round_trip() {
    let mut m = sample();
    m.nodes[1].restart.delay_ms = 250;
    m.nodes[1].stop = Stop {
        mode: StopMode::Cell,
        grace_ms: 3000,
    };
    m.nodes[1].start_timeout_ms = 0;
    m.nodes[3].start_timeout_ms = 12_345;
    let g = m
        .nodes
        .iter()
        .position(|n| !n.groups.is_empty())
        .expect("a node with groups");
    m.nodes[g].groups[0].edges[0].cascade = true;
    let bytes = write(&m).expect("writes");
    let back = open(&bytes).expect("opens").decode();
    assert_eq!(back, m);
}

#[test]
fn launch_fields_and_seccomp_lists_round_trip() {
    let m = sample();
    let bytes = write(&m).expect("written");
    let back = open(&bytes).expect("opened").decode();
    assert_eq!(back, m);
    let logd = back.nodes.iter().find(|n| n.name == "logd").unwrap();
    assert_eq!(logd.env, ["LOGD_DIR=/var/log/qinit"]);
    assert_eq!(
        (logd.cwd.as_str(), logd.umask, logd.rlimit_nofile),
        ("/var/log/qinit", 0o077, 1024)
    );
    assert_eq!(back.creds[0].seccomp, Seccomp::Deny(vec![101, 310]));
}

#[test]
fn an_allow_list_round_trips_in_canonical_decimals() {
    let mut m = sample();
    m.creds[0].seccomp = Seccomp::Allow(vec![0, 7, 511]);
    let bytes = write(&m).expect("written");
    assert_eq!(open(&bytes).expect("opened").decode(), m);
    let pool = word(&bytes, 4 + 2 * T_POOL) as usize;
    let text = &bytes[pool..];
    assert!(
        text.windows(7).any(|w| w == b"0\x007\x00511"),
        "list bytes not found"
    );
}

#[test]
fn a_syscall_number_at_or_above_the_limit_is_refused_by_the_writer() {
    let mut m = sample();
    m.creds[0].seccomp = Seccomp::Allow(vec![512]);
    assert_eq!(write(&m).unwrap_err(), WriteError::Limit("syscall"));
    m.creds[0].seccomp = Seccomp::Deny(Vec::new());
    assert_eq!(write(&m).unwrap_err(), WriteError::Limit("seccomp list"));
}

#[test]
fn an_env_entry_without_a_key_is_refused_by_the_reader_not_the_writer() {
    let m = with_node(|n| n.env = vec!["=x".into()]);
    let bytes = write(&m).expect("the writer checks ranges only");
    assert!(matches!(open(&bytes), Err(ReadError::Db(_))));
}
