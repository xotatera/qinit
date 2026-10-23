// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::time::{Duration, Instant};

use xtask::timing::{self, Parts, Span, Step};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A stream as atc 0.1.0 (protocol 8) wrote it on this host, waiting and
/// paused once, with a line from a later version and a broken one mixed in.
const WAITED_AND_PAUSED: &str = r#"{"event":"started","name":"r/gate:lint","pid":9,"v":1,"t_ms":0}
{"event":"waiting","holders":[{"id":7,"name":"swaplab","phase":"running"}],"v":1,"t_ms":2}
{"event":"admitted","job":4,"waited_ms":600000,"v":1,"t_ms":600000}
{"event":"something-new","v":1,"t_ms":600100}
not json
{"event":"paused","reason":"preempted","by":{"id":8,"name":"swaplab"},"v":1,"t_ms":610000}
{"event":"resumed","paused_ms":12000,"cause":"daemon","v":1,"t_ms":622000}
{"event":"exited","exit":0,"waited_ms":600000,"paused_ms":12000,"ran_ms":90100,"total_ms":702100,"pauses":1,"attempts":1,"job":4,"status":{"code":0},"cpu_ms":610400,"v":1,"t_ms":702100}
"#;

#[test]
fn a_stream_gives_its_holds_and_totals() {
    assert_eq!(
        timing::parse(WAITED_AND_PAUSED),
        Some(Step {
            waited: ms(600_000),
            paused: ms(12_000),
            cpu: Some(ms(610_400)),
            held: vec![(ms(0), ms(600_000)), (ms(610_000), ms(622_000))],
        })
    );
    let quick = r#"{"event":"started","name":"r/x","pid":1,"v":1,"t_ms":0}
{"event":"admitted","job":4,"waited_ms":13,"v":1,"t_ms":13}
{"event":"exited","exit":0,"waited_ms":13,"paused_ms":0,"ran_ms":2800,"total_ms":2814,"pauses":0,"attempts":1,"job":4,"status":{"code":0},"cpu_ms":2795,"v":1,"t_ms":2814}"#;
    assert_eq!(
        timing::parse(quick).map(|s| s.held),
        Some(vec![(ms(0), ms(13))])
    );
}

#[test]
fn an_open_hold_closes_at_exit_and_a_requeue_opens_one() {
    // Never admitted (atc's exit 77): held to the end, no CPU time.
    let never = r#"{"event":"started","name":"r/x","pid":1,"v":1,"t_ms":0}
{"event":"exited","exit":77,"waited_ms":5,"paused_ms":0,"ran_ms":0,"total_ms":5,"pauses":0,"attempts":0,"v":1,"t_ms":5}"#;
    assert_eq!(
        timing::parse(never),
        Some(Step {
            waited: ms(5),
            paused: ms(0),
            cpu: None,
            held: vec![(ms(0), ms(5))],
        })
    );
    // Paused at the end, then requeued and admitted again.
    let requeued = r#"{"event":"admitted","job":4,"waited_ms":0,"v":1,"t_ms":0}
{"event":"requeued","attempt":2,"v":1,"t_ms":10}
{"event":"admitted","job":5,"waited_ms":4,"v":1,"t_ms":14}
{"event":"paused","reason":"capacity","v":1,"t_ms":20}
{"event":"exited","exit":0,"waited_ms":4,"paused_ms":6,"ran_ms":16,"total_ms":26,"pauses":1,"attempts":2,"v":1,"t_ms":26}"#;
    assert_eq!(
        timing::parse(requeued).map(|s| s.held),
        Some(vec![(ms(0), ms(0)), (ms(10), ms(14)), (ms(20), ms(26))])
    );
}

#[test]
fn a_stream_without_a_complete_exit_gives_nothing() {
    assert_eq!(timing::parse(""), None, "an older atc writes nothing");
    let cut = WAITED_AND_PAUSED
        .lines()
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(timing::parse(&cut), None, "a lost stream");
    let no_totals = r#"{"event":"exited","exit":0,"v":1,"t_ms":5}"#;
    assert_eq!(timing::parse(no_totals), None);
}

#[test]
fn a_gates_line_adds_up_its_wall_time() {
    let step = timing::parse(WAITED_AND_PAUSED).unwrap();
    let lint = Parts::of(ms(702_100), std::slice::from_ref(&step));
    assert_eq!(lint.ran(), ms(90_100));
    assert_eq!(
        lint.suffix(false),
        " (702.1s: ran 90.1s, waited 600.0s, paused 12.0s)"
    );
    assert_eq!(
        lint.suffix(true),
        " (702.1s: ran 90.1s, waited 600.0s, paused 12.0s; cpu 610.4s)"
    );
    let quick = Step {
        waited: ms(13),
        cpu: Some(ms(3100)),
        ..Step::default()
    };
    let proof = Parts::of(ms(1700), std::slice::from_ref(&quick));
    assert_eq!(
        proof.suffix(false),
        " (1.7s)",
        "a wait under 0.05 s shows nothing"
    );
    assert_eq!(proof.suffix(true), " (1.7s; cpu 3.1s)");
    // Two steps (a gate with several cargo commands): summed; only the
    // part that is not zero shows.
    let waited = Step {
        waited: ms(2000),
        cpu: None,
        ..Step::default()
    };
    let both = Parts::of(ms(10_000), &[quick, waited]);
    assert_eq!(both.cpu, Some(ms(3100)));
    assert_eq!(both.suffix(false), " (10.0s: ran 8.0s, waited 2.0s)");
    assert_eq!(Parts::of(ms(300), &[]).suffix(true), " (0.3s)");
    assert_eq!(Parts::of(ms(300), &[]).cpu, None);
}

fn span(start: u64, end: u64, held: &[(u64, u64)]) -> Span {
    Span {
        start: ms(start),
        end: ms(end),
        held: held.iter().map(|(a, b)| (ms(*a), ms(*b))).collect(),
    }
}

#[test]
fn the_run_is_held_only_while_every_running_gate_is() {
    assert_eq!(timing::held_total(&[]), Duration::ZERO);
    // One after another: the holds add up; the gap between gates (lookups)
    // is the run's own.
    let serial = [span(0, 100, &[(10, 60)]), span(110, 200, &[(110, 150)])];
    assert_eq!(timing::held_total(&serial), ms(90));
    // Two proofs together: held only while both are.
    let parallel = [span(0, 100, &[(0, 50)]), span(0, 80, &[(20, 80)])];
    assert_eq!(timing::held_total(&parallel), ms(30));
    // One proof works throughout: the run is never held.
    let working = [span(0, 100, &[(0, 100)]), span(0, 100, &[])];
    assert_eq!(timing::held_total(&working), Duration::ZERO);
    // A gate ending while the other is held leaves it alone and held.
    let after = [span(0, 50, &[]), span(0, 100, &[(0, 100)])];
    assert_eq!(timing::held_total(&after), ms(50));
}

#[test]
fn a_span_places_its_steps_holds_in_the_run() {
    let run = Instant::now();
    let gate = run + ms(1000);
    let step = Step {
        held: vec![(ms(0), ms(300)), (ms(400), ms(5000))],
        ..Step::default()
    };
    let s = timing::span(run, gate, ms(2000), &[(gate + ms(100), step)]);
    // Clamped to the gate: a stream's last hold can run past what the gate
    // measured by a few milliseconds.
    assert_eq!(s, span(1000, 3000, &[(1100, 1400), (1500, 3000)]));
}

#[test]
fn a_stream_file_is_new_private_and_removed_or_there_is_none() {
    use std::os::unix::fs::PermissionsExt;
    // atc exits 64 on a target it cannot open: no stream instead.
    let gone = std::env::temp_dir().join(format!("xtask-no-such-dir-{}", std::process::id()));
    assert!(timing::Stream::new_in(&gone, false).is_none());
    let stream = timing::Stream::new(false).unwrap();
    let path = stream.env().1.to_path_buf();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    drop(stream);
    assert!(
        !path.exists(),
        "dropped unread (a panic, an error): removed too"
    );
}

#[test]
fn a_stream_is_recorded_on_its_thread_and_none_when_nested() {
    assert!(timing::Stream::new(true).is_none());
    let _ = timing::take();
    let stream = timing::Stream::new(false).unwrap();
    let (name, path) = stream.env();
    assert_eq!(name, "ATC_EVENTS_TO");
    let path = path.to_path_buf();
    std::fs::write(&path, WAITED_AND_PAUSED).unwrap();
    assert_eq!(stream.finish().map(|s| s.paused), Some(ms(12_000)));
    assert!(!path.exists(), "the stream file is removed");
    let steps = timing::take();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].1.waited, ms(600_000));
    assert_eq!(timing::take().len(), 0, "taken once");
    // Nothing written (an older atc): nothing recorded.
    assert_eq!(timing::Stream::new(false).unwrap().finish(), None);
    assert_eq!(timing::take().len(), 0);
    let other = std::thread::spawn(|| {
        let s = timing::Stream::new(false).unwrap();
        std::fs::write(s.env().1, WAITED_AND_PAUSED).unwrap();
        let _ = s.finish();
    });
    other.join().unwrap();
    assert!(
        timing::take().is_empty(),
        "another thread's step stays there"
    );
}
