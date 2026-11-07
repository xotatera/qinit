// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queen's log lines.
use qinit_queen::kmsg::{format, format_orphans, format_signal, is_failure};
use qinit_queen_core::Mode;
use qinit_queen_core::machine::Event;

fn all_events() -> Vec<Event> {
    let mut v = vec![
        Event::ColonyStarted(i32::MAX),
        Event::ColonyStarted(-1),
        Event::ColonyExited(i32::MIN),
        Event::ColonyExited(0),
        Event::LimitTripped,
        Event::RescueStarted(4_194_304),
        Event::RescueEnded(65_280),
        Event::Hold,
        Event::ExecFailed,
        Event::ChannelBad,
        Event::StoreFull(u64::MAX),
        Event::StoreFull(16),
        Event::SpawnFailed,
        Event::CadIgnored,
    ];
    for m in [Mode::Halt, Mode::Poweroff, Mode::Reboot] {
        v.push(Event::Shutdown(m));
        v.push(Event::ExecZero(m));
    }
    v
}

fn line(ev: &Event) -> String {
    let mut buf = [0u8; 128];
    let n = format(ev, &mut buf);
    assert!(n <= 128);
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

#[test]
fn every_event_formats_within_the_buffer() {
    for ev in all_events() {
        let l = line(&ev);
        assert!(
            l.starts_with("<6>queen: ") || l.starts_with("<3>queen: "),
            "{l:?}"
        );
        assert!(l.ends_with('\n') && l.matches('\n').count() == 1, "{l:?}");
        assert!(!l.contains('\0'), "{l:?}");
    }
    let mut buf = [0u8; 128];
    let n = format_signal(u32::MAX, &mut buf);
    assert!(buf[..n].ends_with(b"\n"));
    let n = format_orphans(u32::MAX, i32::MIN, &mut buf);
    assert!(buf[..n].ends_with(b"\n"));
}

#[test]
fn the_level_is_err_for_failures_and_info_otherwise() {
    for ev in all_events() {
        let failure = matches!(
            ev,
            Event::LimitTripped
                | Event::Hold
                | Event::ExecFailed
                | Event::ChannelBad
                | Event::StoreFull(_)
                | Event::SpawnFailed
        );
        assert_eq!(is_failure(&ev), failure, "{ev:?}");
        let l = line(&ev);
        assert_eq!(l.starts_with("<3>"), failure, "{l:?}");
    }
}

#[test]
fn numbers_are_right_aligned() {
    assert_eq!(
        line(&Event::ColonyStarted(42)),
        "<6>queen: colony started, pid     42\n"
    );
    let mut buf = [0u8; 128];
    let n = format_orphans(3, 1234, &mut buf);
    assert_eq!(
        std::str::from_utf8(&buf[..n]).unwrap(),
        "<6>queen: reaped    3 orphans, last pid   1234\n"
    );
    let n = format_signal(15, &mut buf);
    assert_eq!(
        std::str::from_utf8(&buf[..n]).unwrap(),
        "<6>queen: signal 15 ignored\n"
    );
}
