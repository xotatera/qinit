// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The launch plan: the step list an accepted request resolves to (spec §4), with the proofs
//! that it is well ordered (§7.2) and complete and faithful (§7.3). The runner is one loop
//! over the list; the order lives here, not in the runner.
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::decode::*;
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::spec::*;
#[allow(unused_imports, clippy::wildcard_imports)] // the db-core helpers and spec items
use qinit_db_core::*;
use vstd::prelude::*;

verus! {

/// Steps a plan holds at most.
pub const MAX_STEPS: usize = 256;

/// The highest capability number (`CAP_CHECKPOINT_RESTORE`).
pub const CAP_LAST: u32 = 40;

/// `CAP_SETPCAP`, dropped last among the bounding-set drops.
pub const CAP_SETPCAP: u32 = 8;

/// `CLONE_NEWNS`, for namespace bit 0.
pub const CLONE_NEWNS: u32 = 0x0002_0000;

/// `CLONE_NEWPID`, for namespace bit 1.
pub const CLONE_NEWPID: u32 = 0x2000_0000;

/// `CLONE_NEWIPC`, for namespace bit 2.
pub const CLONE_NEWIPC: u32 = 0x0800_0000;

/// `CLONE_NEWUTS`, for namespace bit 3.
pub const CLONE_NEWUTS: u32 = 0x0400_0000;

/// `CLONE_NEWNET`, for namespace bit 4.
pub const CLONE_NEWNET: u32 = 0x4000_0000;

/// `SECBIT_KEEP_CAPS`: always set, since the kernel clears it at exec.
pub const SECBIT_KEEP_CAPS: u32 = 16;

/// `SECBIT_NOROOT`.
pub const SECBIT_NOROOT: u32 = 1;

/// `SECBIT_NOROOT_LOCKED`.
pub const SECBIT_NOROOT_LOCKED: u32 = 2;

/// One step of the launch. A step carries only values that come from the request or from a
/// named constant; the runner reads everything else from the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `setsid()`.
    Setsid,
    /// `unshare(flags)` with the `CLONE_NEW*` bits of the requested namespaces.
    Unshare(u32),
    /// `MS_SLAVE | MS_REC` on `/`.
    MountSlaveRoot,
    /// A private `tmpfs` on `/tmp`.
    MountTmp,
    /// `lo` up in the new network namespace.
    LoopbackUp,
    /// Fork into the new pid namespace; the child continues.
    Fork,
    /// Arm the deadline timer, in milliseconds.
    ArmDeadline(u32),
    /// Standard input from `/dev/null`.
    OpenStdin,
    /// Standard output from the request's stream.
    OpenStdout,
    /// Standard error from the request's stream.
    OpenStderr,
    /// The readiness pipe arrives on this descriptor.
    RouteReady(u32),
    /// `umask(mask)`.
    Umask(u32),
    /// The limit of this kernel resource number (soft and hard) to this value; `u64::MAX` is
    /// infinity.
    Rlimit(u32, u64),
    /// `RLIMIT_CORE` to 0.
    RlimitCore0,
    /// `setgroups` of the resolved supplementary groups.
    Setgroups,
    /// `setresgid` of the resolved group.
    Setgid,
    /// `PR_SET_SECUREBITS` with these bits.
    Securebits(u32),
    /// `PR_CAPBSET_DROP` of this capability.
    DropBounding(u32),
    /// `setresuid` of the resolved user.
    Setuid,
    /// `capset` of the requested set.
    Capset,
    /// `PR_CAP_AMBIENT_RAISE` of this capability.
    AmbientRaise(u32),
    /// `PR_SET_PDEATHSIG`.
    Pdeathsig,
    /// `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
    /// `chdir` as the user.
    Chdir,
    /// `landlock_create_ruleset`.
    LandlockRuleset,
    /// `landlock_add_rule` for the entry at this index of the request's list.
    LandlockRule(u32),
    /// `landlock_restrict_self`.
    LandlockRestrict,
    /// Install the seccomp program.
    Seccomp,
    /// `close_range(4, ~0, 0)`.
    CloseRange,
    /// `execve`.
    Exec,
}

/// The phase of a step: the coarse position in the launch sequence of spec §4.
pub open spec fn phase(s: Step) -> int {
    match s {
        Step::Setsid => 0,
        Step::Unshare(_) => 1,
        Step::MountSlaveRoot => 1,
        Step::MountTmp => 1,
        Step::LoopbackUp => 1,
        Step::Fork => 2,
        Step::ArmDeadline(_) => 3,
        Step::OpenStdin => 4,
        Step::OpenStdout => 4,
        Step::OpenStderr => 4,
        Step::RouteReady(_) => 4,
        Step::Umask(_) => 5,
        Step::Rlimit(_, _) => 5,
        Step::RlimitCore0 => 5,
        Step::Setgroups => 6,
        Step::Setgid => 6,
        Step::Securebits(_) => 7,
        Step::DropBounding(_) => 8,
        Step::Setuid => 9,
        Step::Capset => 10,
        Step::AmbientRaise(_) => 11,
        Step::Pdeathsig => 12,
        Step::NoNewPrivs => 13,
        Step::Chdir => 14,
        Step::LandlockRuleset => 15,
        Step::LandlockRule(_) => 16,
        Step::LandlockRestrict => 17,
        Step::Seccomp => 18,
        Step::CloseRange => 19,
        Step::Exec => 20,
    }
}

/// The position of a step within its phase.
pub open spec fn sub(s: Step) -> int {
    match s {
        Step::MountSlaveRoot => 1,
        Step::MountTmp => 2,
        Step::LoopbackUp => 3,
        Step::OpenStdout => 1,
        Step::OpenStderr => 2,
        Step::RouteReady(_) => 3,
        Step::Rlimit(r, _) => 1 + r as int,
        Step::RlimitCore0 => 17,
        Step::Setgid => 1,
        Step::DropBounding(c) => if c == CAP_SETPCAP {
            41
        } else {
            c as int
        },
        Step::AmbientRaise(c) => c as int,
        Step::LandlockRule(i) => i as int,
        _ => 0,
    }
}

/// `x` comes strictly before `y` in the launch order.
pub open spec fn before(x: Step, y: Step) -> bool {
    phase(x) < phase(y) || (phase(x) == phase(y) && sub(x) < sub(y))
}

/// Strictly increasing in the launch order: no step twice, none out of place.
pub open spec fn sorted(s: Seq<Step>) -> bool {
    forall|i: int, j: int| 0 <= i < j < s.len() ==> before(#[trigger] s[i], #[trigger] s[j])
}

/// The ordering obligation of spec §7.2: the list is strictly increasing in the launch order
/// and ends with `Exec`. The clauses follow from the phase table (see
/// [`lemma_phase_table`]).
pub open spec fn well_ordered(s: Seq<Step>) -> bool {
    &&& sorted(s)
    &&& s.len() >= 1
    &&& s.last() == Step::Exec
}

/// The clauses of spec §7.2, each read off the phase table: outputs before any credential
/// step; securebits and drops before `setresuid`; `capset` and the raises after it; the
/// death signal after the last credential step; no-new-privs after the credentials and before
/// Landlock; Landlock before seccomp; `chdir` after `setresuid`; the fork before the deadline
/// and the outputs; `execve` last.
pub proof fn lemma_phase_table(c: u32, i: u32, f: u32)
    ensures
        phase(Step::Fork) < phase(Step::ArmDeadline(f)),
        phase(Step::ArmDeadline(f)) < phase(Step::OpenStdout),
        phase(Step::OpenStdout) < phase(Step::Setgroups),
        phase(Step::Setgid) < phase(Step::Securebits(f)),
        phase(Step::Securebits(f)) < phase(Step::Setuid),
        phase(Step::DropBounding(c)) < phase(Step::Setuid),
        phase(Step::Setuid) < phase(Step::Capset),
        phase(Step::Capset) < phase(Step::AmbientRaise(c)),
        phase(Step::AmbientRaise(c)) < phase(Step::Pdeathsig),
        phase(Step::Pdeathsig) < phase(Step::NoNewPrivs),
        phase(Step::Setuid) < phase(Step::NoNewPrivs),
        phase(Step::NoNewPrivs) < phase(Step::LandlockRuleset),
        phase(Step::LandlockRuleset) < phase(Step::LandlockRule(i)),
        phase(Step::LandlockRule(i)) < phase(Step::LandlockRestrict),
        phase(Step::LandlockRestrict) < phase(Step::Seccomp),
        phase(Step::Setuid) < phase(Step::Chdir),
        phase(Step::Chdir) < phase(Step::LandlockRuleset),
        phase(Step::Seccomp) < phase(Step::CloseRange),
        phase(Step::CloseRange) < phase(Step::Exec),
{
}

/// The step `x` occurs in `s`.
pub open spec fn has(s: Seq<Step>, x: Step) -> bool {
    exists|k: int| 0 <= k < s.len() && s[k] == x
}

/// Capability `c` is in the request's set.
pub open spec fn cap_has(b: Seq<u8>, c: int) -> bool {
    if c < 32 {
        ((qw(b, Q_CAPS_LO) as u32) >> (c as u32)) & 1u32 == 1u32
    } else {
        ((qw(b, Q_CAPS_HI) as u32) >> ((c - 32) as u32)) & 1u32 == 1u32
    }
}

/// The securebits the request's preset stands for: `KEEP_CAPS` always, `NOROOT` for both
/// presets and `NOROOT_LOCKED` for the locked one.
pub open spec fn sb_value(sb: int) -> int {
    (SECBIT_KEEP_CAPS as int) + (if sb >= 1 {
        SECBIT_NOROOT as int
    } else {
        0int
    }) + (if sb == 2 {
        SECBIT_NOROOT_LOCKED as int
    } else {
        0int
    })
}

/// The Landlock entries of the request.
pub open spec fn paths_elems(b: Seq<u8>) -> int {
    elems(field_slice(b, Q_PATHS_OFF, Q_PATHS_LEN))
}

/// Bit `r` of the request's limit mask.
pub open spec fn rlimit_set(b: Seq<u8>, r: int) -> bool {
    ((qw(b, Q_RLIMIT_MASK) as u32) >> (r as u32)) & 1u32 == 1u32
}

/// The value of limit `r` of the request: its low word plus its high word times 2^32.
pub open spec fn rlimit_value(b: Seq<u8>, r: int) -> int {
    qw(b, (Q_RLIMIT_BASE + 2 * r) as usize) + qw(b, (Q_RLIMIT_BASE + 2 * r + 1) as usize)
        * 0x1_0000_0000
}

/// A step the request calls for: a payload that is a request field or a named constant, and
/// a presence the request's flags allow.
pub open spec fn step_ok(b: Seq<u8>, x: Step) -> bool {
    match x {
        Step::Unshare(f) => qw(b, Q_NS) != 0 && f as int == ns_flags(qw(b, Q_NS) as u32),
        Step::MountSlaveRoot => ((qw(b, Q_NS) as u32) & 1u32) != 0u32,
        Step::MountTmp => ((qw(b, Q_NS) as u32) & 1u32) != 0u32,
        Step::LoopbackUp => ((qw(b, Q_NS) as u32) & 16u32) != 0u32,
        Step::Fork => ((qw(b, Q_NS) as u32) & 2u32) != 0u32,
        Step::ArmDeadline(d) => d as int == qw(b, Q_DEADLINE_MS),
        Step::RouteReady(fd) => qw(b, Q_READY_KIND) == READY_PIPE && fd as int == qw(b, Q_READY_FD),
        Step::Umask(m) => m as int == qw(b, Q_UMASK),
        Step::Rlimit(r, v) => r < RLIMIT_COUNT as u32 && rlimit_set(b, r as int) && v as int
            == rlimit_value(b, r as int),
        Step::Securebits(v) => v as int == sb_value(qw(b, Q_SECUREBITS)),
        Step::DropBounding(c) => c <= CAP_LAST && !cap_has(b, c as int),
        Step::AmbientRaise(c) => c <= CAP_LAST && cap_has(b, c as int),
        Step::Pdeathsig => ((qw(b, Q_FLAGS) as u32) & 1u32) != 0u32,
        Step::NoNewPrivs => qw(b, Q_NNP) == 1,
        Step::LandlockRuleset => qw(b, Q_PATHS_LEN) > 0,
        Step::LandlockRule(i) => (i as int) < paths_elems(b),
        Step::LandlockRestrict => qw(b, Q_PATHS_LEN) > 0,
        Step::Seccomp => qw(b, Q_SECCOMP) != 0,
        _ => true,
    }
}

/// Every step of `s` is one the request calls for.
pub open spec fn faithful(b: Seq<u8>, s: Seq<Step>) -> bool {
    forall|k: int| 0 <= k < s.len() ==> step_ok(b, #[trigger] s[k])
}

/// `t` has every step `s` has.
pub open spec fn ext(s: Seq<Step>, t: Seq<Step>) -> bool {
    forall|y: Step| has(s, y) ==> #[trigger] has(t, y)
}

/// Namespaces: the unshare, the mount steps, the fork and the loopback.
pub open spec fn present_ns(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& has(s, Step::Setsid)
    &&& (qw(b, Q_NS) != 0 ==> has(s, Step::Unshare(ns_flags(qw(b, Q_NS) as u32) as u32)))
    &&& (((qw(b, Q_NS) as u32) & 1u32) != 0u32 ==> has(s, Step::MountSlaveRoot) && has(
        s,
        Step::MountTmp,
    ))
    &&& (((qw(b, Q_NS) as u32) & 2u32) != 0u32 ==> has(s, Step::Fork))
    &&& (((qw(b, Q_NS) as u32) & 16u32) != 0u32 ==> has(s, Step::LoopbackUp))
}

/// The deadline and the descriptors.
pub open spec fn present_fds(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& has(s, Step::ArmDeadline(qw(b, Q_DEADLINE_MS) as u32))
    &&& has(s, Step::OpenStdin)
    &&& has(s, Step::OpenStdout)
    &&& has(s, Step::OpenStderr)
    &&& (qw(b, Q_READY_KIND) == READY_PIPE ==> has(s, Step::RouteReady(qw(b, Q_READY_FD) as u32)))
}

/// The mask, limits, groups and securebits.
pub open spec fn present_env(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& has(s, Step::Umask(qw(b, Q_UMASK) as u32))
    &&& forall|r: int|
        0 <= r < RLIMIT_COUNT && rlimit_set(b, r) ==> #[trigger] has(
            s,
            Step::Rlimit(r as u32, rlimit_value(b, r) as u64),
        )
    &&& has(s, Step::RlimitCore0)
    &&& has(s, Step::Setgroups)
    &&& has(s, Step::Setgid)
    &&& has(s, Step::Securebits(sb_value(qw(b, Q_SECUREBITS)) as u32))
}

/// Every capability outside the set is dropped from the bounding set.
pub open spec fn present_drops(b: Seq<u8>, s: Seq<Step>) -> bool {
    forall|c: int|
        0 <= c <= CAP_LAST ==> (!cap_has(b, c) ==> #[trigger] has(s, Step::DropBounding(c as u32)))
}

/// The user change, `capset`, and every capability in the set raised.
pub open spec fn present_creds(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& has(s, Step::Setuid)
    &&& has(s, Step::Capset)
    &&& forall|c: int|
        0 <= c <= CAP_LAST ==> (cap_has(b, c) ==> #[trigger] has(s, Step::AmbientRaise(c as u32)))
}

/// The death signal, no-new-privs and `chdir`.
pub open spec fn present_tail(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& (((qw(b, Q_FLAGS) as u32) & 1u32) != 0u32 ==> has(s, Step::Pdeathsig))
    &&& (qw(b, Q_NNP) == 1 ==> has(s, Step::NoNewPrivs))
    &&& has(s, Step::Chdir)
}

/// The Landlock ruleset, one rule per entry, and the restriction.
pub open spec fn present_landlock(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& (qw(b, Q_PATHS_LEN) > 0 ==> has(s, Step::LandlockRuleset) && has(s, Step::LandlockRestrict))
    &&& forall|i: int| 0 <= i < paths_elems(b) ==> #[trigger] has(s, Step::LandlockRule(i as u32))
}

/// Seccomp, `close_range` and `execve`.
pub open spec fn present_finish(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& (qw(b, Q_SECCOMP) != 0 ==> has(s, Step::Seccomp))
    &&& has(s, Step::CloseRange)
    &&& has(s, Step::Exec)
}

/// Everything the request calls for occurs in `s`.
pub open spec fn present(b: Seq<u8>, s: Seq<Step>) -> bool {
    &&& present_ns(b, s)
    &&& present_fds(b, s)
    &&& present_env(b, s)
    &&& present_drops(b, s)
    &&& present_creds(b, s)
    &&& present_tail(b, s)
    &&& present_landlock(b, s)
    &&& present_finish(b, s)
}

/// Presence only grows with the list.
pub proof fn lemma_present_mono(b: Seq<u8>, s: Seq<Step>, t: Seq<Step>)
    requires
        ext(s, t),
    ensures
        present_ns(b, s) ==> present_ns(b, t),
        present_fds(b, s) ==> present_fds(b, t),
        present_env(b, s) ==> present_env(b, t),
        present_drops(b, s) ==> present_drops(b, t),
        present_creds(b, s) ==> present_creds(b, t),
        present_tail(b, s) ==> present_tail(b, t),
        present_landlock(b, s) ==> present_landlock(b, t),
        present_finish(b, s) ==> present_finish(b, t),
{
}

/// `ext` is transitive.
pub proof fn lemma_ext_trans(r: Seq<Step>, s: Seq<Step>, t: Seq<Step>)
    requires
        ext(r, s),
        ext(s, t),
    ensures
        ext(r, t),
{
}

/// The completeness and faithfulness obligation of spec §7.3. Together with
/// [`well_ordered`] (strictly increasing, so no step twice) every capability is raised or
/// dropped exactly once, and every Landlock entry and routed descriptor appears exactly once.
pub open spec fn complete(b: Seq<u8>, s: Seq<Step>) -> bool {
    faithful(b, s) && present(b, s)
}

/// Writes `s` at `out[n]` and returns the new length. The step must come after the last one.
#[allow(unused_variables)]  // `b` appears only in the contract
fn emit(b: &[u8], out: &mut [Step; MAX_STEPS], n: usize, s: Step) -> (m: usize)
    requires
        n < MAX_STEPS,
        sorted(old(out)@.take(n as int)),
        n == 0 || before(old(out)@[n - 1], s),
        faithful(b@, old(out)@.take(n as int)),
        step_ok(b@, s),
    ensures
        m == n + 1,
        faithful(b@, final(out)@.take(m as int)),
        has(final(out)@.take(m as int), s),
        forall|y: Step|
            has(old(out)@.take(n as int), y) ==> #[trigger] has(final(out)@.take(m as int), y),
        final(out)@.len() == old(out)@.len(),
        final(out)@.take(m as int) =~= old(out)@.take(n as int).push(s),
        final(out)@[n as int] == s,
        forall|k: int| 0 <= k < n ==> final(out)@[k] == old(out)@[k],
        sorted(final(out)@.take(m as int)),
{
    out[n] = s;
    proof {
        let t = out@.take((n + 1) as int);
        let old_t = old(out)@.take(n as int);
        assert(t =~= old_t.push(s));
        assert(t[n as int] == s);
        assert forall|k: int| 0 <= k < t.len() implies step_ok(b@, #[trigger] t[k]) by {
            if k < n {
                assert(t[k] == old_t[k]);
            }
        }
        assert forall|y: Step| has(old_t, y) implies #[trigger] has(t, y) by {
            let k = choose|k: int| 0 <= k < old_t.len() && old_t[k] == y;
            assert(t[k] == y);
        }
        assert forall|i: int, j: int| 0 <= i < j < t.len() implies before(
            #[trigger] t[i],
            #[trigger] t[j],
        ) by {
            if j == n as int {
                assert(t[j] == s);
                if i == n - 1 {
                    assert(t[i] == old(out)@[n - 1]);
                } else {
                    assert(before(old_t[i], old_t[n - 1]));
                    assert(old_t[n - 1] == old(out)@[n - 1]);
                    assert(t[i] == old_t[i]);
                }
            } else {
                assert(t[i] == old_t[i] && t[j] == old_t[j]);
            }
        }
    }
    n + 1
}

/// The `CLONE_NEW*` flags of namespace bits `ns`, summed (the five flags are distinct bits).
pub open spec fn ns_flags(ns: u32) -> int {
    (if ns & 1u32 != 0 {
        CLONE_NEWNS as int
    } else {
        0int
    }) + (if ns & 2u32 != 0 {
        CLONE_NEWPID as int
    } else {
        0int
    }) + (if ns & 4u32 != 0 {
        CLONE_NEWIPC as int
    } else {
        0int
    }) + (if ns & 8u32 != 0 {
        CLONE_NEWUTS as int
    } else {
        0int
    }) + (if ns & 16u32 != 0 {
        CLONE_NEWNET as int
    } else {
        0int
    })
}

/// The last step of `t[..n]` sits before position `(p, k)`: an earlier phase, or phase `p` at
/// a position below `k`.
pub open spec fn below(t: Seq<Step>, n: int, p: int, k: int) -> bool {
    &&& n > 0
    &&& phase(t[n - 1]) < p || (phase(t[n - 1]) == p && sub(t[n - 1]) < k)
}

/// Whether capability `c` is in the request's set.
fn cap_bit(b: &[u8], c: u32) -> (r: bool)
    requires
        accepted(b@),
        c <= CAP_LAST,
    ensures
        r == cap_has(b@, c as int),
{
    if c < 32 {
        (req(b, Q_CAPS_LO) >> c) & 1 == 1
    } else {
        (req(b, Q_CAPS_HI) >> (c - 32)) & 1 == 1
    }
}

/// The `CLONE_NEW*` flags of the namespace bits `ns`.
#[allow(clippy::many_single_char_names)]  // one letter per namespace flag
fn flags_of(ns: u32) -> (f: u32)
    requires
        ns <= 0x1f,
    ensures
        f as int == ns_flags(ns),
{
    let a = if ns & 1 != 0 {
        CLONE_NEWNS
    } else {
        0
    };
    let p = if ns & 2 != 0 {
        CLONE_NEWPID
    } else {
        0
    };
    let i = if ns & 4 != 0 {
        CLONE_NEWIPC
    } else {
        0
    };
    let u = if ns & 8 != 0 {
        CLONE_NEWUTS
    } else {
        0
    };
    let n = if ns & 16 != 0 {
        CLONE_NEWNET
    } else {
        0
    };
    a + p + i + u + n
}

/// Phases 0 to 2: `setsid`, the namespaces and the fork.
fn sec_ns(b: &[u8], out: &mut [Step; MAX_STEPS]) -> (m: usize)
    requires
        accepted(b@),
    ensures
        m <= 6,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        below(final(out)@, m as int, 3, 0),
        present_ns(b@, final(out)@.take(m as int)),
{
    let ns = req(b, Q_NS);
    assert(ns <= 0x1f);
    let flags = flags_of(ns);
    let mut n: usize = 0;
    assert(sorted(out@.take(0)));
    assert(faithful(b@, out@.take(0)));
    n = emit(b, out, n, Step::Setsid);
    if ns != 0 {
        n = emit(b, out, n, Step::Unshare(flags));
    }
    assert(below(out@, n as int, 1, 1));
    if ns & 1 != 0 {
        n = emit(b, out, n, Step::MountSlaveRoot);
        n = emit(b, out, n, Step::MountTmp);
    }
    assert(below(out@, n as int, 1, 3));
    if ns & 16 != 0 {
        n = emit(b, out, n, Step::LoopbackUp);
    }
    assert(below(out@, n as int, 1, 4));
    if ns & 2 != 0 {
        n = emit(b, out, n, Step::Fork);
    }
    n
}

/// Phases 3 and 4: the deadline and the descriptors.
fn sec_fds(b: &[u8], out: &mut [Step; MAX_STEPS], n0: usize) -> (m: usize)
    requires
        accepted(b@),
        n0 <= 6,
        sorted(old(out)@.take(n0 as int)),
        faithful(b@, old(out)@.take(n0 as int)),
        below(old(out)@, n0 as int, 3, 0),
    ensures
        n0 < m <= n0 + 5,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        below(final(out)@, m as int, 5, 0),
        ext(old(out)@.take(n0 as int), final(out)@.take(m as int)),
        present_fds(b@, final(out)@.take(m as int)),
{
    let mut n = n0;
    n = emit(b, out, n, Step::ArmDeadline(req(b, Q_DEADLINE_MS)));
    n = emit(b, out, n, Step::OpenStdin);
    n = emit(b, out, n, Step::OpenStdout);
    n = emit(b, out, n, Step::OpenStderr);
    if req(b, Q_READY_KIND) == READY_PIPE {
        n = emit(b, out, n, Step::RouteReady(req(b, Q_READY_FD)));
    }
    n
}

/// Phases 5 to 7: the mask, limits, groups and securebits.
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]  // `r < RLIMIT_COUNT`; `u64::from` is not available inside `verus!`
fn sec_env(b: &[u8], out: &mut [Step; MAX_STEPS], n0: usize) -> (m: usize)
    requires
        accepted(b@),
        n0 <= 11,
        sorted(old(out)@.take(n0 as int)),
        faithful(b@, old(out)@.take(n0 as int)),
        below(old(out)@, n0 as int, 5, 0),
    ensures
        n0 < m <= n0 + 21,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        below(final(out)@, m as int, 8, 0),
        ext(old(out)@.take(n0 as int), final(out)@.take(m as int)),
        present_env(b@, final(out)@.take(m as int)),
{
    let sbv = SECBIT_KEEP_CAPS + (if req(b, Q_SECUREBITS) >= 1 {
        SECBIT_NOROOT
    } else {
        0
    }) + (if req(b, Q_SECUREBITS) == 2 {
        SECBIT_NOROOT_LOCKED
    } else {
        0
    });
    assert(sbv as int == sb_value(qw(b@, Q_SECUREBITS)));
    let mut n = n0;
    n = emit(b, out, n, Step::Umask(req(b, Q_UMASK)));
    let mask = req(b, Q_RLIMIT_MASK);
    let mut r: usize = 0;
    while r < RLIMIT_COUNT
        invariant
            accepted(b@),
            r <= RLIMIT_COUNT,
            n0 + 1 <= n <= n0 + 1 + r,
            n0 <= 11,
            mask as int == qw(b@, Q_RLIMIT_MASK),
            out@.len() == old(out)@.len(),
            sorted(out@.take(n as int)),
            faithful(b@, out@.take(n as int)),
            ext(old(out)@.take(n0 as int), out@.take(n as int)),
            has(out@.take(n as int), Step::Umask(qw(b@, Q_UMASK) as u32)),
            phase(out@[n - 1]) < 5 || (phase(out@[n - 1]) == 5 && sub(out@[n - 1]) < 1 + r),
            forall|j: int|
                0 <= j < r && rlimit_set(b@, j) ==> #[trigger] has(
                    out@.take(n as int),
                    Step::Rlimit(j as u32, rlimit_value(b@, j) as u64),
                ),
        decreases RLIMIT_COUNT - r,
    {
        if (mask >> (r as u32)) & 1 == 1 {
            let lo = req(b, Q_RLIMIT_BASE + 2 * r);
            let hi = req(b, Q_RLIMIT_BASE + 2 * r + 1);
            let v: u64 = (hi as u64) * 0x1_0000_0000u64 + (lo as u64);
            assert(v as int == rlimit_value(b@, r as int));
            n = emit(b, out, n, Step::Rlimit(r as u32, v));
        }
        r += 1;
    }
    assert(below(out@, n as int, 5, 17));
    let ghost t_limits = out@.take(n as int);
    n = emit(b, out, n, Step::RlimitCore0);
    let ghost t_core = out@.take(n as int);
    n = emit(b, out, n, Step::Setgroups);
    let ghost t_groups = out@.take(n as int);
    n = emit(b, out, n, Step::Setgid);
    let ghost t_gid = out@.take(n as int);
    n = emit(b, out, n, Step::Securebits(sbv));
    proof {
        let t = out@.take(n as int);
        let um = Step::Umask(qw(b@, Q_UMASK) as u32);
        assert(has(t_limits, um));
        assert(has(t_core, um));
        assert(has(t_groups, um));
        assert(has(t_gid, um));
        assert forall|j: int| 0 <= j < RLIMIT_COUNT && rlimit_set(b@, j) implies #[trigger] has(
            t,
            Step::Rlimit(j as u32, rlimit_value(b@, j) as u64),
        ) by {
            let x = Step::Rlimit(j as u32, rlimit_value(b@, j) as u64);
            assert(has(t_limits, x));
            assert(has(t_core, x));
            assert(has(t_groups, x));
            assert(has(t_gid, x));
        }
    }
    n
}

/// Phase 8: every capability outside the set is dropped from the bounding set,
/// `CAP_SETPCAP` last.
fn sec_drops(b: &[u8], out: &mut [Step; MAX_STEPS], n0: usize) -> (m: usize)
    requires
        accepted(b@),
        n0 <= 32,
        sorted(old(out)@.take(n0 as int)),
        faithful(b@, old(out)@.take(n0 as int)),
        below(old(out)@, n0 as int, 8, 0),
    ensures
        n0 <= m <= n0 + 42,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        below(final(out)@, m as int, 9, 0),
        ext(old(out)@.take(n0 as int), final(out)@.take(m as int)),
        present_drops(b@, final(out)@.take(m as int)),
{
    let mut n = n0;
    let mut c: u32 = 0;
    while c <= CAP_LAST
        invariant
            accepted(b@),
            c <= CAP_LAST + 1,
            n0 <= n <= n0 + c,
            n0 <= 32,
            n <= 32 + 41,
            out@.len() == old(out)@.len(),
            sorted(out@.take(n as int)),
            faithful(b@, out@.take(n as int)),
            ext(old(out)@.take(n0 as int), out@.take(n as int)),
            n > 0,
            phase(out@[n - 1]) < 8 || (phase(out@[n - 1]) == 8 && sub(out@[n - 1]) < c as int),
            forall|d: int|
                0 <= d < c as int && d != CAP_SETPCAP as int && !cap_has(b@, d) ==> #[trigger] has(
                    out@.take(n as int),
                    Step::DropBounding(d as u32),
                ),
        decreases CAP_LAST + 1 - c,
    {
        if c != CAP_SETPCAP && !cap_bit(b, c) {
            n = emit(b, out, n, Step::DropBounding(c));
        }
        c += 1;
    }
    if !cap_bit(b, CAP_SETPCAP) {
        n = emit(b, out, n, Step::DropBounding(CAP_SETPCAP));
    }
    n
}

/// Phases 9 to 11: the user change, `capset` and the ambient raises.
fn sec_creds(b: &[u8], out: &mut [Step; MAX_STEPS], n0: usize) -> (m: usize)
    requires
        accepted(b@),
        n0 <= 74,
        sorted(old(out)@.take(n0 as int)),
        faithful(b@, old(out)@.take(n0 as int)),
        below(old(out)@, n0 as int, 9, 0),
    ensures
        n0 + 2 <= m <= n0 + 43,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        below(final(out)@, m as int, 12, 0),
        ext(old(out)@.take(n0 as int), final(out)@.take(m as int)),
        present_creds(b@, final(out)@.take(m as int)),
{
    let mut n = n0;
    n = emit(b, out, n, Step::Setuid);
    n = emit(b, out, n, Step::Capset);
    #[allow(unused_variables)]  // `base` appears only in the invariants
    let base = n;
    let mut c: u32 = 0;
    while c <= CAP_LAST
        invariant
            accepted(b@),
            c <= CAP_LAST + 1,
            base <= n <= base + c,
            base == n0 + 2,
            n0 <= 74,
            n <= 74 + 2 + 41,
            out@.len() == old(out)@.len(),
            sorted(out@.take(n as int)),
            faithful(b@, out@.take(n as int)),
            ext(old(out)@.take(n0 as int), out@.take(n as int)),
            n > 0,
            has(out@.take(n as int), Step::Setuid),
            has(out@.take(n as int), Step::Capset),
            phase(out@[n - 1]) < 11 || (phase(out@[n - 1]) == 11 && sub(out@[n - 1]) < c as int),
            forall|d: int|
                0 <= d < c as int && cap_has(b@, d) ==> #[trigger] has(
                    out@.take(n as int),
                    Step::AmbientRaise(d as u32),
                ),
        decreases CAP_LAST + 1 - c,
    {
        if cap_bit(b, c) {
            n = emit(b, out, n, Step::AmbientRaise(c));
        }
        c += 1;
    }
    n
}

/// Phases 12 to 14: the death signal, no-new-privs and `chdir`.
fn sec_tail(b: &[u8], out: &mut [Step; MAX_STEPS], n0: usize) -> (m: usize)
    requires
        accepted(b@),
        n0 <= 117,
        sorted(old(out)@.take(n0 as int)),
        faithful(b@, old(out)@.take(n0 as int)),
        below(old(out)@, n0 as int, 12, 0),
    ensures
        n0 < m <= n0 + 3,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        below(final(out)@, m as int, 15, 0),
        ext(old(out)@.take(n0 as int), final(out)@.take(m as int)),
        present_tail(b@, final(out)@.take(m as int)),
{
    let mut n = n0;
    if req(b, Q_FLAGS) & 1 != 0 {
        n = emit(b, out, n, Step::Pdeathsig);
    }
    assert(below(out@, n as int, 13, 0));
    if req(b, Q_NNP) == 1 {
        n = emit(b, out, n, Step::NoNewPrivs);
    }
    n = emit(b, out, n, Step::Chdir);
    n
}

/// Phases 15 to 17: the Landlock ruleset, one rule per entry, the restriction.
#[allow(clippy::cast_possible_truncation)]  // the index is below MAX_PATH_ENTRIES
fn sec_landlock(b: &[u8], out: &mut [Step; MAX_STEPS], n0: usize) -> (m: usize)
    requires
        accepted(b@),
        n0 <= 120,
        sorted(old(out)@.take(n0 as int)),
        faithful(b@, old(out)@.take(n0 as int)),
        below(old(out)@, n0 as int, 15, 0),
    ensures
        n0 <= m <= n0 + 66,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        below(final(out)@, m as int, 18, 0),
        ext(old(out)@.take(n0 as int), final(out)@.take(m as int)),
        present_landlock(b@, final(out)@.take(m as int)),
{
    let ll_len = req(b, Q_PATHS_LEN);
    let ll_rules = {
        assert(req_pool_ref(b@, qw(b@, Q_PATHS_OFF), qw(b@, Q_PATHS_LEN)));
        count_elements(pool(b, req(b, Q_PATHS_OFF), ll_len))
    };
    assert(ll_rules as int == paths_elems(b@));
    assert(ll_rules <= MAX_PATH_ENTRIES);
    let mut n = n0;
    if ll_len > 0 {
        n = emit(b, out, n, Step::LandlockRuleset);
        #[allow(unused_variables)]  // `base` appears only in the invariants
        let base = n;
        let mut i: usize = 0;
        while i < ll_rules
            invariant
                accepted(b@),
                ll_rules as int == paths_elems(b@),
                ll_rules <= MAX_PATH_ENTRIES,
                i <= ll_rules,
                base <= n <= base + i,
                base == n0 + 1,
                n0 <= 120,
                n <= 120 + 1 + 64,
                out@.len() == old(out)@.len(),
                sorted(out@.take(n as int)),
                faithful(b@, out@.take(n as int)),
                ext(old(out)@.take(n0 as int), out@.take(n as int)),
                has(out@.take(n as int), Step::LandlockRuleset),
                n > 0,
                phase(out@[n - 1]) < 16 || (phase(out@[n - 1]) == 16 && sub(out@[n - 1])
                    < i as int),
                forall|d: int|
                    0 <= d < i as int ==> #[trigger] has(
                        out@.take(n as int),
                        Step::LandlockRule(d as u32),
                    ),
            decreases ll_rules - i,
        {
            n = emit(b, out, n, Step::LandlockRule(i as u32));  // i < 64
            i += 1;
        }
        n = emit(b, out, n, Step::LandlockRestrict);
    }
    n
}

/// Phases 18 to 20: seccomp, `close_range` and `execve`.
fn sec_finish(b: &[u8], out: &mut [Step; MAX_STEPS], n0: usize) -> (m: usize)
    requires
        accepted(b@),
        n0 <= 186,
        sorted(old(out)@.take(n0 as int)),
        faithful(b@, old(out)@.take(n0 as int)),
        below(old(out)@, n0 as int, 18, 0),
    ensures
        n0 + 2 <= m <= n0 + 3,
        final(out)@.len() == old(out)@.len(),
        sorted(final(out)@.take(m as int)),
        faithful(b@, final(out)@.take(m as int)),
        final(out)@[m - 1] == Step::Exec,
        ext(old(out)@.take(n0 as int), final(out)@.take(m as int)),
        present_finish(b@, final(out)@.take(m as int)),
{
    let mut n = n0;
    if req(b, Q_SECCOMP) != 0 {
        n = emit(b, out, n, Step::Seccomp);
    }
    n = emit(b, out, n, Step::CloseRange);
    n = emit(b, out, n, Step::Exec);
    n
}

/// Resolves an accepted request to its launch steps, written to `out[..n]`; returns `n`.
///
/// The list is strictly increasing in the launch order, so each step occurs at most once, ends
/// with `Exec`, and holds exactly the steps the request calls for ([`complete`]).
pub fn plan(b: &[u8], out: &mut [Step; MAX_STEPS]) -> (n: usize)
    requires
        accepted(b@),
    ensures
        n <= MAX_STEPS,
        well_ordered(final(out)@.take(n as int)),
        complete(b@, final(out)@.take(n as int)),
{
    let n1 = sec_ns(b, out);
    let ghost t1 = out@.take(n1 as int);
    let n1b = sec_fds(b, out, n1);
    let ghost t1b = out@.take(n1b as int);
    let n2 = sec_env(b, out, n1b);
    let ghost t2 = out@.take(n2 as int);
    let n3 = sec_drops(b, out, n2);
    let ghost t3 = out@.take(n3 as int);
    let n4 = sec_creds(b, out, n3);
    let ghost t4 = out@.take(n4 as int);
    let n5 = sec_tail(b, out, n4);
    let ghost t5 = out@.take(n5 as int);
    let n6 = sec_landlock(b, out, n5);
    let ghost t6 = out@.take(n6 as int);
    let n7 = sec_finish(b, out, n6);
    let ghost t7 = out@.take(n7 as int);
    proof {
        lemma_ext_trans(t1, t1b, t2);
        lemma_ext_trans(t1b, t2, t3);
        lemma_ext_trans(t1b, t3, t4);
        lemma_ext_trans(t1b, t4, t5);
        lemma_ext_trans(t1b, t5, t6);
        lemma_ext_trans(t1b, t6, t7);
        lemma_present_mono(b@, t1b, t7);
        lemma_ext_trans(t1, t1b, t7);
        lemma_ext_trans(t1, t2, t3);
        lemma_ext_trans(t1, t3, t4);
        lemma_ext_trans(t1, t4, t5);
        lemma_ext_trans(t1, t5, t6);
        lemma_ext_trans(t1, t6, t7);
        lemma_ext_trans(t2, t3, t4);
        lemma_ext_trans(t2, t4, t5);
        lemma_ext_trans(t2, t5, t6);
        lemma_ext_trans(t2, t6, t7);
        lemma_ext_trans(t3, t4, t5);
        lemma_ext_trans(t3, t5, t6);
        lemma_ext_trans(t3, t6, t7);
        lemma_ext_trans(t4, t5, t6);
        lemma_ext_trans(t4, t6, t7);
        lemma_ext_trans(t5, t6, t7);
        lemma_present_mono(b@, t1, t7);
        lemma_present_mono(b@, t2, t7);
        lemma_present_mono(b@, t3, t7);
        lemma_present_mono(b@, t4, t7);
        lemma_present_mono(b@, t5, t7);
        lemma_present_mono(b@, t6, t7);
        assert(t7.last() == out@[n7 - 1]);
    }
    n7
}

} // verus!
