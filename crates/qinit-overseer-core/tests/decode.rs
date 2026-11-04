// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The launch request decoder: every rule of `accepted`, one patch at a time.
mod common;

use common::*;
use qinit_overseer_core::*;

#[test]
fn a_valid_minimal_request_is_accepted() {
    assert_eq!(decode(&valid()), Ok(()));
}

#[test]
fn a_wrong_magic_or_version_is_a_header_error() {
    let db = with(&valid(), |w| w[H_MAGIC] += 1);
    assert_eq!(decode(&db), Err(LaunchError::Header));
    let db = with(&valid(), |w| w[H_VERSION] = 2);
    assert_eq!(decode(&db), Err(LaunchError::Header));
    assert_eq!(decode(&valid()[..10]), Err(LaunchError::Header));
    assert_eq!(decode(&[]), Err(LaunchError::Header));
}

#[test]
fn a_total_length_that_disagrees_is_a_header_error() {
    let db = with(&valid(), |w| w[H_TOTAL_LEN] -= 1);
    assert_eq!(decode(&db), Err(LaunchError::Header));
    let mut longer = valid();
    longer.push(0);
    assert_eq!(decode(&longer), Err(LaunchError::Header));
    let db = with(&valid(), |w| w[H_POOL_OFF] -= 4);
    assert_eq!(decode(&db), Err(LaunchError::Header));
    let db = with(&valid(), |w| w[H_POOL_LEN] -= 1);
    assert_eq!(decode(&db), Err(LaunchError::Header));
}

#[test]
fn an_empty_argv_is_a_consistency_error() {
    let mut spec = minimal();
    spec.argv = "";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
}

#[test]
fn a_pool_reference_past_the_pool_is_a_pool_error() {
    let db = with(&valid(), |w| {
        let pool_len = w[H_POOL_LEN];
        w[at(Q_USER_OFF)] = pool_len;
    });
    assert_eq!(decode(&db), Err(LaunchError::Pool));
    let db = with(&valid(), |w| w[at(Q_USER_LEN)] = u32::MAX);
    assert_eq!(decode(&db), Err(LaunchError::Pool));
}

#[test]
fn invalid_utf8_in_the_pool_is_a_pool_error() {
    let mut db = valid();
    let i = pool_at(&db, 0);
    db[i] = 0xff;
    assert_eq!(decode(&db), Err(LaunchError::Pool));
}

#[test]
fn an_empty_list_element_is_a_pool_error() {
    let mut spec = minimal();
    spec.env = "A=1\0\0B=2";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Pool));
}

#[test]
fn enums_are_bounded() {
    for (w, v) in [
        (Q_SECUREBITS, 3),
        (Q_NNP, 2),
        (Q_NS, 0x20),
        (Q_SECCOMP, 4),
        (Q_STDOUT_KIND, 2),
        (Q_STDERR_KIND, 3),
        (Q_READY_KIND, 2),
        (Q_FLAGS, 2),
        (Q_UMASK, 0o1000),
        (Q_CAPS_HI, 0x200),
        (Q_RESERVED_0, 1),
        (Q_RESERVED_1, 1),
    ] {
        let db = with(&valid(), |x| x[at(w)] = v);
        assert_eq!(decode(&db), Err(LaunchError::Enum), "word {w}");
    }
}

#[test]
fn routed_fds_are_in_range_and_distinct() {
    let mut spec = minimal();
    spec.ready = Some(4);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.ready = Some(5);
    assert_eq!(decode(&build(&spec)), Ok(()));
    spec.stdout = Stream::Fd(5);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.stdout = Stream::Fd(6);
    spec.stderr = Stream::Fd(6);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.stderr = Stream::Fd(37);
    assert_eq!(decode(&build(&spec)), Ok(()));
    spec.stderr = Stream::Fd(38);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
}

#[test]
fn a_zero_deadline_is_a_consistency_error() {
    let mut spec = minimal();
    spec.deadline_ms = 0;
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
}

#[test]
fn a_relative_cwd_or_a_bad_env_entry_is_a_consistency_error() {
    let mut spec = minimal();
    spec.cwd = "tmp";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.cwd = "";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    let mut spec = minimal();
    spec.env = "=x";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.env = "A=1\0B=";
    assert_eq!(decode(&build(&spec)), Ok(()));
}

#[test]
fn an_empty_user_is_a_consistency_error() {
    let mut spec = minimal();
    spec.user = "";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
}

#[test]
fn the_seccomp_list_matches_its_mode() {
    let mut spec = minimal();
    spec.seccomp = 1;
    spec.seccomp_list = "101";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Enum));
    spec.seccomp = 2;
    spec.seccomp_list = "";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Enum));
    spec.seccomp_list = "0\x00101\x00511";
    assert_eq!(decode(&build(&spec)), Ok(()));
    spec.seccomp = 3;
    assert_eq!(decode(&build(&spec)), Ok(()));
    for bad in ["512", "01", "1a", "1000"] {
        spec.seccomp_list = bad;
        assert_eq!(
            decode(&build(&spec)),
            Err(LaunchError::Consistency),
            "{bad:?}"
        );
    }
}

#[test]
fn landlock_entries_are_ro_or_rw_paths() {
    let mut spec = minimal();
    spec.paths = "ro:/etc\0rw:/run/x";
    assert_eq!(decode(&build(&spec)), Ok(()));
    for bad in ["/etc", "rx:/etc", "ro:etc", "ro:"] {
        spec.paths = bad;
        assert_eq!(
            decode(&build(&spec)),
            Err(LaunchError::Consistency),
            "{bad:?}"
        );
    }
}

#[test]
fn non_canonical_entries_and_cwd_are_refused() {
    for bad in ["ro:/a/..", "rw:/tmp/", "ro://x", "rw:/dev/.", "ro:/a//b"] {
        let mut spec = minimal();
        spec.paths = bad;
        assert_eq!(
            decode(&build(&spec)),
            Err(LaunchError::Consistency),
            "{bad:?}"
        );
    }
    for bad in ["/a/..", "/a/", "//a", "/a/./b"] {
        let mut spec = minimal();
        spec.cwd = bad;
        assert_eq!(
            decode(&build(&spec)),
            Err(LaunchError::Consistency),
            "{bad:?}"
        );
    }
}

#[test]
fn too_many_list_entries_is_a_consistency_error() {
    let paths: &'static str = Box::leak(
        (0..65)
            .map(|i| format!("ro:/p{i}"))
            .collect::<Vec<_>>()
            .join("\0")
            .into_boxed_str(),
    );
    let mut spec = minimal();
    spec.paths = paths;
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    let env: &'static str = Box::leak(
        (0..257)
            .map(|i| format!("K{i}=v"))
            .collect::<Vec<_>>()
            .join("\0")
            .into_boxed_str(),
    );
    let mut spec = minimal();
    spec.env = env;
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    let list: &'static str = Box::leak(
        (0..513)
            .map(|i| (i % 512).to_string())
            .collect::<Vec<_>>()
            .join("\0")
            .into_boxed_str(),
    );
    let mut spec = minimal();
    spec.seccomp = 3;
    spec.seccomp_list = list;
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
}

#[test]
fn nnp_off_with_a_sandbox_needs_sys_admin() {
    let mut spec = minimal();
    spec.nnp = 0;
    assert_eq!(decode(&build(&spec)), Ok(()));
    spec.seccomp = 1;
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.caps = 1 << 21;
    assert_eq!(decode(&build(&spec)), Ok(()));
    spec.caps = 0;
    spec.seccomp = 0;
    spec.paths = "ro:/etc";
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
}

#[test]
fn a_request_above_the_size_limit_is_a_header_error() {
    let env: &'static str = Box::leak("A=".to_owned().into_boxed_str());
    let mut spec = minimal();
    spec.env = env;
    let big: &'static str = Box::leak(format!("A={}", "x".repeat(MAX_REQUEST)).into_boxed_str());
    spec.env = big;
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Header));
}

#[test]
fn accessors_read_what_was_laid_out() {
    let db = valid();
    assert_eq!(decode(&db), Ok(()));
    assert_eq!(req(&db, Q_UMASK), 0o027);
    assert_eq!(req(&db, Q_DEADLINE_MS), 1000);
    assert_eq!(word(&db, H_VERSION), LAUNCH_VERSION);
    assert_eq!(
        pool(&db, req(&db, Q_USER_OFF), req(&db, Q_USER_LEN)),
        b"svc"
    );
    assert_eq!(
        pool(&db, req(&db, Q_ARGV_OFF), req(&db, Q_ARGV_LEN)),
        b"/bin/true"
    );
}

#[test]
fn stdin_defaults_to_a_path() {
    let db = valid();
    assert_eq!(req(&db, Q_STDIN_KIND), STREAM_PATH);
    assert_eq!(
        pool(&db, req(&db, Q_STDIN_A), req(&db, Q_STDIN_B)),
        b"/dev/null"
    );
}

#[test]
fn a_stdin_fd_must_be_in_range_and_distinct() {
    let mut spec = minimal();
    spec.stdin = Stream::Fd(5);
    assert_eq!(decode(&build(&spec)), Ok(()));
    spec.stdout = Stream::Fd(5);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.stdout = Stream::Path("/dev/null");
    spec.stderr = Stream::Fd(5);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.stderr = Stream::Same;
    spec.ready = Some(5);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.ready = None;
    spec.stdin = Stream::Fd(4);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.stdin = Stream::Fd(38);
    assert_eq!(decode(&build(&spec)), Err(LaunchError::Consistency));
    spec.stdin = Stream::Fd(37);
    assert_eq!(decode(&build(&spec)), Ok(()));
}

#[test]
fn a_stdin_kind_of_2_is_an_enum_error() {
    let db = with(&valid(), |w| w[at(Q_STDIN_KIND)] = STREAM_SAME);
    assert_eq!(decode(&db), Err(LaunchError::Enum));
}

#[test]
fn a_stdin_path_outside_the_pool_is_a_pool_error() {
    let db = with(&valid(), |w| {
        let pool_len = w[H_POOL_LEN];
        w[at(Q_STDIN_A)] = pool_len;
    });
    assert_eq!(decode(&db), Err(LaunchError::Pool));
}

#[test]
fn a_stdin_fd_has_no_length() {
    let mut spec = minimal();
    spec.stdin = Stream::Fd(6);
    let db = with(&build(&spec), |w| w[at(Q_STDIN_B)] = 1);
    assert_eq!(decode(&db), Err(LaunchError::Consistency));
}

/// The minimal request with node limits set by `f`.
fn limited(f: impl FnOnce(&mut [Option<u64>; 16])) -> Vec<u8> {
    let mut spec = minimal();
    f(&mut spec.rlimits);
    build(&spec)
}

#[test]
fn rlimit_rules_match_the_database() {
    // A valid full mask (every resource but core) is accepted.
    let full = limited(|l| {
        for (r, v) in l.iter_mut().enumerate() {
            *v = (r != 4).then_some(match r {
                13 | 14 => 9,
                _ => 1 << 33,
            });
        }
    });
    assert_eq!(decode(&full), Ok(()));
    let edge = limited(|l| {
        l[13] = Some(40);
        l[14] = Some(99);
        l[6] = Some(u64::MAX);
        l[7] = Some(1);
    });
    assert_eq!(decode(&edge), Ok(()));
    // The core bit and bit 16 are enum errors.
    assert_eq!(decode(&limited(|l| l[4] = Some(0))), Err(LaunchError::Enum));
    let mut b = build(&minimal());
    let w = 4 * (HEADER_WORDS + Q_RLIMIT_MASK);
    b[w..w + 4].copy_from_slice(&(1u32 << 16).to_le_bytes());
    assert_eq!(decode(&b), Err(LaunchError::Enum));
    // An unset limit with a value.
    let mut b = build(&minimal());
    let w = 4 * (HEADER_WORDS + Q_RLIMIT_BASE + 2 * 6);
    b[w..w + 4].copy_from_slice(&5u32.to_le_bytes());
    assert_eq!(decode(&b), Err(LaunchError::Consistency));
    // ... and in its high word.
    let mut b = build(&minimal());
    b[w + 4..w + 8].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(decode(&b), Err(LaunchError::Consistency));
    for bad in [
        limited(|l| l[7] = Some(0)),
        limited(|l| l[7] = Some(u64::MAX)),
        limited(|l| l[13] = Some(41)),
        limited(|l| l[14] = Some(100)),
        limited(|l| l[13] = Some(1 << 32)),
    ] {
        assert_eq!(decode(&bad), Err(LaunchError::Consistency));
    }
}
