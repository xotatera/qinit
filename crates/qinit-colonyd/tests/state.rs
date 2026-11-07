// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The text colony keeps in queen's store: what a line says, and that one bad line refuses all.
use qinit_colony::{Counters, Reason, SavedTerminal};
use qinit_colonyd::state::{
    CellLine, NodeLine, PipeLine, format_cells, format_nodes, parse_cells, parse_nodes,
};

fn cells() -> Vec<CellLine> {
    vec![
        CellLine {
            name: "db".into(),
            cgroup_id: 901,
            ready: true,
            dir_key: 16,
            main_key: 17,
        },
        CellLine {
            name: "job#4".into(),
            cgroup_id: 77,
            ready: false,
            dir_key: 18,
            main_key: 0,
        },
    ]
}

fn nodes() -> Vec<NodeLine> {
    let counters = Counters {
        burst_begin_ms: 10,
        burst_count: 4,
        backoff_exp: 2,
        last_start_ms: 30,
        ended_ms: 40,
    };
    vec![
        NodeLine {
            name: "a".into(),
            wanted: true,
            terminal: None,
            counters: Counters::default(),
        },
        NodeLine {
            name: "crashy".into(),
            wanted: true,
            terminal: Some(SavedTerminal::Quarantined(Reason::Breaker)),
            counters,
        },
        NodeLine {
            name: "job".into(),
            wanted: false,
            terminal: Some(SavedTerminal::Done),
            counters: Counters::default(),
        },
    ]
}

fn pipes() -> Vec<PipeLine> {
    vec![
        PipeLine {
            logger: "syslogger".into(),
            read: 20,
            write: 21,
        },
        PipeLine {
            logger: "other".into(),
            read: 22,
            write: 23,
        },
    ]
}

#[test]
fn cells_round_trip() {
    let text = format_cells(&cells());
    assert_eq!(text, "db 901 1 16 17\njob#4 77 0 18 0\n");
    assert_eq!(parse_cells(&text), Ok(cells()));
    assert_eq!(parse_cells(""), Ok(Vec::new()));
}

#[test]
fn nodes_and_pipes_round_trip() {
    let text = format_nodes(&nodes(), &pipes());
    assert_eq!(parse_nodes(&text), Ok((nodes(), pipes())));
    assert!(text.contains("\npipe syslogger 20 21\n"), "{text}");
    assert_eq!(parse_nodes(""), Ok((Vec::new(), Vec::new())));
}

#[test]
fn every_quarantine_reason_round_trips() {
    let lines: Vec<NodeLine> = [
        Reason::Breaker,
        Reason::Cascade,
        Reason::StartTimeout,
        Reason::StopFailed,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, r)| NodeLine {
        name: format!("n{i}"),
        wanted: true,
        terminal: Some(SavedTerminal::Quarantined(r)),
        counters: Counters::default(),
    })
    .collect();
    assert_eq!(
        parse_nodes(&format_nodes(&lines, &[])),
        Ok((lines, Vec::new()))
    );
}

#[test]
fn a_bad_line_refuses_the_whole_text() {
    for bad in [
        "db 901 1 16\n",
        "db x 1 16 17\n",
        "db 901 2 16 17\n",
        "db 901 1 0 17\n",
        "db 901 1 16 17 18\n",
        "db 901 1 16 -1\n",
    ] {
        let text = format!("good 1 0 5 0\n{bad}");
        let e = parse_cells(&text).unwrap_err();
        assert!(e.contains("line 2"), "{bad:?}: {e}");
    }
    for bad in [
        "a 1 off 0 0 0 0\n",
        "a 2 off 0 0 0 0 0\n",
        "a 1 quarantined:nope 0 0 0 0 0\n",
        "a 1 sleeping 0 0 0 0 0\n",
        "pipe l 0 5\n",
        "pipe l 5 0\n",
        "pipe l x 5\n",
        "pipe l 5\n",
    ] {
        let text = format!("fine 1 off 0 0 0 0 0\n{bad}");
        let e = parse_nodes(&text).unwrap_err();
        assert!(e.contains("line 2"), "{bad:?}: {e}");
    }
    assert!(
        parse_nodes("fine 1 off 0 0 0 0 0\n\n  \n").is_ok(),
        "blank lines are skipped"
    );
}

#[test]
fn a_node_named_pipe_is_not_a_pipe_line() {
    let n = NodeLine {
        name: "pipe".into(),
        wanted: true,
        terminal: None,
        counters: Counters::default(),
    };
    let text = format_nodes(std::slice::from_ref(&n), &pipes());
    let (nodes, got) = parse_nodes(&text).unwrap();
    assert_eq!(nodes, [n]);
    assert_eq!(got, pipes());
}
