// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The seccomp program generator (spec §7): a fixed-shape classic-BPF filter built from a list
//! of syscall numbers, with the proof that it kills foreign architectures, that every jump
//! stays inside the program, and what it answers for every system call.
//!
//! A program is: the architecture check (four instructions); in a denylist mode, a block of 16
//! instructions for the x32 range and the calls with their own rule (`setns`, `clone3`, `clone`
//! and `unshare`); one `JEQ`/`RET` pair per listed number; and a final `RET`. Jumps are
//! relative and eight bits wide, so every pair holds its own `RET`; no jump is longer than
//! four instructions.

#[allow(unused_imports, clippy::wildcard_imports)] // spec-only use: Verus erases it
use crate::layout::*;
use vstd::prelude::*;

verus! {

/// Entries of [`DEFAULT_DENY`].
pub const DEFAULT_DENY_LEN: usize = 42;

/// The default denylist (spec §7): one row per call with the reason. Sorted by number;
/// `setns`, `clone3`, `clone` and `unshare` are not here, they have their own block in a
/// denylist program. `qinit-frames` checks every name against its `x86_64` table.
pub const DEFAULT_DENY: [u32; DEFAULT_DENY_LEN] = [
    101,  // ptrace: traces another process
    134,  // uselib: obsolete library loading
    139,  // sysfs: obsolete filesystem-type query
    154,  // modify_ldt: x86 descriptor-table editing
    155,  // pivot_root: mount family
    156,  // _sysctl: removed sysctl interface
    159,  // adjtimex: sets the clock
    163,  // acct: process accounting file
    164,  // settimeofday: sets the clock
    165,  // mount: mount family
    166,  // umount2: mount family
    167,  // swapon: swap control
    168,  // swapoff: swap control
    169,  // reboot
    172,  // iopl: raw I/O privilege
    173,  // ioperm: raw I/O privilege
    174,  // create_module: kernel module loading (removed)
    175,  // init_module: kernel module loading
    176,  // delete_module: kernel module unloading
    177,  // get_kernel_syms: kernel module query (removed)
    178,  // query_module: kernel module query (removed)
    180,  // nfsservctl: removed NFS server control
    227,  // clock_settime: sets the clock
    246,  // kexec_load: replaces the kernel
    248,  // add_key: kernel keyring
    249,  // request_key: kernel keyring
    250,  // keyctl: kernel keyring
    298,  // perf_event_open: performance counters
    305,  // clock_adjtime: sets the clock
    310,  // process_vm_readv: reads another process
    311,  // process_vm_writev: writes another process
    313,  // finit_module: kernel module loading
    320,  // kexec_file_load: replaces the kernel
    321,  // bpf: loads kernel programs
    323,  // userfaultfd: stalls the kernel on page faults
    428,  // open_tree: mount family
    429,  // move_mount: mount family
    430,  // fsopen: mount family
    431,  // fsconfig: mount family
    432,  // fsmount: mount family
    433,  // fspick: mount family
    442,  // mount_setattr: mount family
];

/// Entries one program may list: a frame's `MAX_SECCOMP_LIST` plus the default denylist.
pub const MAX_FILTER_LIST: usize = MAX_SECCOMP_LIST + 64;

/// Instructions a program holds at most: the check, the special block, two per entry, a `RET`.
pub const MAX_BPF: usize = 4 + 2 * MAX_FILTER_LIST + 16 + 1;

/// `AUDIT_ARCH_X86_64`.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `SECCOMP_RET_ALLOW`.
pub const RET_ALLOW: u32 = 0x7fff_0000;

/// `SECCOMP_RET_KILL_PROCESS`.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;

/// `SECCOMP_RET_ERRNO`; the errno is `OR`ed into the low 16 bits.
pub const RET_ERRNO: u32 = 0x0005_0000;

/// `SECCOMP_RET_ERRNO | EPERM`.
pub const RET_EPERM: u32 = 0x0005_0001;

/// `SECCOMP_RET_ERRNO | ENOSYS`.
pub const RET_ENOSYS: u32 = 0x0005_0026;

/// The first number of the x32 range (`__X32_SYSCALL_BIT`).
pub const X32_BIT: u32 = 0x4000_0000;

/// `clone`.
pub const NR_CLONE: u32 = 56;

/// `unshare`.
pub const NR_UNSHARE: u32 = 272;

/// `setns`.
pub const NR_SETNS: u32 = 308;

/// `clone3`.
pub const NR_CLONE3: u32 = 435;

/// Every `CLONE_NEW*` bit: namespaces for mount, UTS, IPC, user, pid, net, cgroup and time.
pub const CLONE_NEW_ANY: u32 = 0x7E02_0080;

/// `BPF_LD | BPF_W | BPF_ABS`.
pub const BPF_LD_W_ABS: u16 = 0x20;

/// `BPF_JMP | BPF_JEQ | BPF_K`.
pub const BPF_JEQ_K: u16 = 0x15;

/// `BPF_JMP | BPF_JSET | BPF_K`.
pub const BPF_JSET_K: u16 = 0x45;

/// `BPF_JMP | BPF_JGE | BPF_K`.
pub const BPF_JGE_K: u16 = 0x35;

/// `BPF_RET | BPF_K`.
pub const BPF_RET_K: u16 = 0x06;

/// One classic-BPF instruction (`struct sock_filter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// The opcode.
    pub code: u16,
    /// Jump offset when the test holds.
    pub jt: u8,
    /// Jump offset when it does not.
    pub jf: u8,
    /// The immediate.
    pub k: u32,
}

/// Instructions of the special block of a denylist program.
pub open spec fn special_len(mode: u32) -> int {
    if mode == 3 {
        0
    } else {
        16
    }
}

/// Index of the first list pair.
pub open spec fn base(mode: u32) -> int {
    4 + special_len(mode)
}

/// Length of the program for `mode` and `list`.
pub open spec fn plen(mode: u32, list: Seq<u32>) -> int {
    base(mode) + 2 * list.len() + 1
}

/// The verdict of a listed number: denied in a denylist, allowed in an allowlist.
pub open spec fn hit(mode: u32) -> u32 {
    if mode == 3 {
        RET_ALLOW
    } else {
        RET_EPERM
    }
}

/// The verdict of an unlisted number.
pub open spec fn miss(mode: u32) -> u32 {
    if mode == 3 {
        RET_EPERM
    } else {
        RET_ALLOW
    }
}

/// A spec-level instruction.
pub open spec fn mk(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}

/// The instruction at index `j` of the special block.
pub open spec fn special_at(j: int) -> Insn {
    if j == 0 {
        mk(BPF_JGE_K, 0, 1, X32_BIT)
    } else if j == 1 {
        mk(BPF_RET_K, 0, 0, RET_KILL_PROCESS)
    } else if j == 2 {
        mk(BPF_JEQ_K, 0, 1, NR_SETNS)
    } else if j == 3 {
        mk(BPF_RET_K, 0, 0, RET_EPERM)
    } else if j == 4 {
        mk(BPF_JEQ_K, 0, 1, NR_CLONE3)
    } else if j == 5 {
        mk(BPF_RET_K, 0, 0, RET_ENOSYS)
    } else if j == 6 {
        mk(BPF_JEQ_K, 0, 4, NR_CLONE)
    } else if j == 7 {
        mk(BPF_LD_W_ABS, 0, 0, 16)
    } else if j == 8 {
        mk(BPF_JSET_K, 0, 1, CLONE_NEW_ANY)
    } else if j == 9 {
        mk(BPF_RET_K, 0, 0, RET_EPERM)
    } else if j == 10 {
        mk(BPF_RET_K, 0, 0, RET_ALLOW)
    } else if j == 11 {
        mk(BPF_JEQ_K, 0, 4, NR_UNSHARE)
    } else if j == 12 {
        mk(BPF_LD_W_ABS, 0, 0, 16)
    } else if j == 13 {
        mk(BPF_JSET_K, 0, 1, CLONE_NEW_ANY)
    } else if j == 14 {
        mk(BPF_RET_K, 0, 0, RET_EPERM)
    } else {
        mk(BPF_RET_K, 0, 0, RET_ALLOW)
    }
}

/// The part of the program before the list pairs: the architecture check and, in a denylist
/// mode, the special block.
pub open spec fn fixed_at(mode: u32, k: int) -> Insn {
    if k == 0 {
        mk(BPF_LD_W_ABS, 0, 0, 4)
    } else if k == 1 {
        mk(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64)
    } else if k == 2 {
        mk(BPF_RET_K, 0, 0, RET_KILL_PROCESS)
    } else if k == 3 {
        mk(BPF_LD_W_ABS, 0, 0, 0)
    } else {
        special_at(k - 4)
    }
}

/// The instruction at index `k` of the program for `mode` and `list`.
pub open spec fn insn_at(mode: u32, list: Seq<u32>, k: int) -> Insn {
    if k < base(mode) {
        fixed_at(mode, k)
    } else if k < base(mode) + 2 * list.len() {
        if (k - base(mode)) % 2 == 0 {
            mk(BPF_JEQ_K, 0, 1, list[(k - base(mode)) / 2])
        } else {
            mk(BPF_RET_K, 0, 0, hit(mode))
        }
    } else {
        mk(BPF_RET_K, 0, 0, miss(mode))
    }
}

/// The accumulator after loading the word at offset `k` of `seccomp_data`.
pub open spec fn load(arch: u32, nr: u32, arg0: u32, k: u32) -> u32 {
    if k == 0 {
        nr
    } else if k == 4 {
        arch
    } else if k == 16 {
        arg0
    } else {
        0
    }
}

/// What the kernel's classic-BPF interpreter returns for the program of `mode` and `list`
/// from instruction `pc` with accumulator `acc`, on a call with `arch`, `nr` and `arg0`. A jump
/// out of the program kills; a well-formed program never makes one.
pub open spec fn run(
    mode: u32,
    list: Seq<u32>,
    arch: u32,
    nr: u32,
    arg0: u32,
    pc: int,
    acc: u32,
) -> u32
    decreases plen(mode, list) - pc,
{
    if pc < 0 || pc >= plen(mode, list) {
        RET_KILL_PROCESS
    } else {
        let i = insn_at(mode, list, pc);
        if i.code == BPF_LD_W_ABS {
            run(mode, list, arch, nr, arg0, pc + 1, load(arch, nr, arg0, i.k))
        } else if i.code == BPF_RET_K {
            i.k
        } else {
            let holds = if i.code == BPF_JEQ_K {
                acc == i.k
            } else if i.code == BPF_JSET_K {
                acc & i.k != 0
            } else {
                acc >= i.k
            };
            let t = pc + 1 + (if holds {
                i.jt as int
            } else {
                i.jf as int
            });
            if t >= plen(mode, list) {
                RET_KILL_PROCESS
            } else {
                run(mode, list, arch, nr, arg0, t, acc)
            }
        }
    }
}

/// The verdict for a system call.
pub open spec fn verdict(mode: u32, list: Seq<u32>, arch: u32, nr: u32, arg0: u32) -> u32 {
    run(mode, list, arch, nr, arg0, 0, 0)
}

/// `nr` is in `list` from index `i` on.
pub open spec fn listed_from(list: Seq<u32>, nr: u32, i: int) -> bool {
    exists|j: int| i <= j < list.len() && list[j] == nr
}

/// The program is well formed: only the five opcodes, every jump target inside, ending in a
/// `RET`, beginning with the architecture check.
pub open spec fn bpf_wf(mode: u32, list: Seq<u32>) -> bool {
    &&& forall|k: int|
        0 <= k < plen(mode, list) ==> {
            let i = #[trigger] insn_at(mode, list, k);
            &&& i.code == BPF_LD_W_ABS || i.code == BPF_JEQ_K || i.code == BPF_JSET_K || i.code
                == BPF_JGE_K || i.code == BPF_RET_K
            &&& (i.code == BPF_JEQ_K || i.code == BPF_JSET_K || i.code == BPF_JGE_K) ==> (k + 1 + (
            i.jt as int) < plen(mode, list)) && (k + 1 + (i.jf as int) < plen(mode, list))
        }
    &&& insn_at(mode, list, plen(mode, list) - 1).code == BPF_RET_K
    &&& insn_at(mode, list, 0) == mk(BPF_LD_W_ABS, 0, 0, 4)
    &&& insn_at(mode, list, 1) == mk(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64)
    &&& insn_at(mode, list, 2) == mk(BPF_RET_K, 0, 0, RET_KILL_PROCESS)
    &&& insn_at(mode, list, 3) == mk(BPF_LD_W_ABS, 0, 0, 0)
}

/// `hit` as an executable value.
fn hit_value(mode: u32) -> (r: u32)
    ensures
        r == hit(mode),
{
    if mode == 3 {
        RET_ALLOW
    } else {
        RET_EPERM
    }
}

/// `miss` as an executable value.
fn miss_value(mode: u32) -> (r: u32)
    ensures
        r == miss(mode),
{
    if mode == 3 {
        RET_EPERM
    } else {
        RET_ALLOW
    }
}

/// Writes `i` at `out[k]`.
fn put(out: &mut [Insn; MAX_BPF], k: usize, i: Insn)
    requires
        k < MAX_BPF,
    ensures
        final(out)@ == old(out)@.update(k as int, i),
{
    out[k] = i;
}

/// Writes the architecture check and, in a denylist mode, the special block.
fn fill_fixed(mode: u32, out: &mut [Insn; MAX_BPF])
    requires
        1 <= mode <= 3,
    ensures
        final(out)@.len() == old(out)@.len(),
        forall|k: int| 0 <= k < base(mode) ==> final(out)@[k] == fixed_at(mode, k),
{
    put(out, 0, Insn { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 4 });
    put(out, 1, Insn { code: BPF_JEQ_K, jt: 1, jf: 0, k: AUDIT_ARCH_X86_64 });
    put(out, 2, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_KILL_PROCESS });
    put(out, 3, Insn { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 });
    if mode != 3 {
        put(out, 4, Insn { code: BPF_JGE_K, jt: 0, jf: 1, k: X32_BIT });
        put(out, 5, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_KILL_PROCESS });
        put(out, 6, Insn { code: BPF_JEQ_K, jt: 0, jf: 1, k: NR_SETNS });
        put(out, 7, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_EPERM });
        put(out, 8, Insn { code: BPF_JEQ_K, jt: 0, jf: 1, k: NR_CLONE3 });
        put(out, 9, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_ENOSYS });
        put(out, 10, Insn { code: BPF_JEQ_K, jt: 0, jf: 4, k: NR_CLONE });
        put(out, 11, Insn { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 16 });
        put(out, 12, Insn { code: BPF_JSET_K, jt: 0, jf: 1, k: CLONE_NEW_ANY });
        put(out, 13, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_EPERM });
        put(out, 14, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_ALLOW });
        put(out, 15, Insn { code: BPF_JEQ_K, jt: 0, jf: 4, k: NR_UNSHARE });
        put(out, 16, Insn { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 16 });
        put(out, 17, Insn { code: BPF_JSET_K, jt: 0, jf: 1, k: CLONE_NEW_ANY });
        put(out, 18, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_EPERM });
        put(out, 19, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: RET_ALLOW });
    }
    assert forall|k: int| 0 <= k < base(mode) implies out@[k] == fixed_at(mode, k) by {
        if k >= 4 {
            assert(special_at(k - 4) == fixed_at(mode, k));
        }
    };
}

/// Builds the seccomp program of `mode` (1 default denylist, 2 deny, 3 allow) over `list`
/// into `out[..n]`. For mode 1 `list` is the default denylist, for mode 2 the default
/// denylist followed by the frame's entries, for mode 3 the frame's entries.
pub fn program(mode: u32, list: &[u32], out: &mut [Insn; MAX_BPF]) -> (n: usize)
    requires
        1 <= mode <= 3,
        list@.len() <= MAX_FILTER_LIST,
    ensures
        n as int == plen(mode, list@),
        n <= MAX_BPF,
        final(out)@.len() == old(out)@.len(),
        forall|k: int| 0 <= k < n ==> final(out)@[k] == insn_at(mode, list@, k),
{
    fill_fixed(mode, out);
    let first: usize = if mode == 3 {
        4
    } else {
        20
    };
    assert(first as int == base(mode));
    let hit_v = hit_value(mode);
    let miss_v = miss_value(mode);
    let mut i: usize = 0;
    while i < list.len()
        invariant
            1 <= mode <= 3,
            first as int == base(mode),
            list@.len() <= MAX_FILTER_LIST,
            i <= list.len(),
            hit_v == hit(mode),
            out@.len() == MAX_BPF,
            forall|k: int|
                0 <= k < first as int + 2 * i as int ==> out@[k] == insn_at(mode, list@, k),
        decreases list.len() - i,
    {
        put(out, first + 2 * i, Insn { code: BPF_JEQ_K, jt: 0, jf: 1, k: list[i] });
        put(out, first + 2 * i + 1, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: hit_v });
        i += 1;
    }
    let end = first + 2 * list.len();
    put(out, end, Insn { code: BPF_RET_K, jt: 0, jf: 0, k: miss_v });
    end + 1
}

/// The scan of the list pairs from pair `i`: the first listed number answers `hit`, an
/// unlisted one falls through to `miss`.
pub proof fn lemma_scan(mode: u32, list: Seq<u32>, arch: u32, nr: u32, arg0: u32, i: int)
    requires
        1 <= mode <= 3,
        0 <= i <= list.len(),
    ensures
        run(mode, list, arch, nr, arg0, base(mode) + 2 * i, nr) == if listed_from(list, nr, i) {
            hit(mode)
        } else {
            miss(mode)
        },
    decreases list.len() - i,
{
    reveal_with_fuel(run, 3);
    if i < list.len() {
        lemma_scan(mode, list, arch, nr, arg0, i + 1);
        if list[i] == nr {
            assert(listed_from(list, nr, i));
        } else {
            assert(listed_from(list, nr, i) == listed_from(list, nr, i + 1)) by {
                if listed_from(list, nr, i) {
                    let j = choose|j: int| i <= j < list.len() && list[j] == nr;
                    assert(j >= i + 1);
                }
            }
        }
    }
}

/// What the program answers for every system call (spec §7.5).
pub proof fn lemma_verdict(mode: u32, list: Seq<u32>, arch: u32, nr: u32, arg0: u32)
    requires
        1 <= mode <= 3,
    ensures
        arch != AUDIT_ARCH_X86_64 ==> verdict(mode, list, arch, nr, arg0) == RET_KILL_PROCESS,
        arch == AUDIT_ARCH_X86_64 && mode == 3 ==> verdict(mode, list, arch, nr, arg0)
            == if listed_from(list, nr, 0) {
            RET_ALLOW
        } else {
            RET_EPERM
        },
        arch == AUDIT_ARCH_X86_64 && mode != 3 && nr >= X32_BIT ==> verdict(
            mode,
            list,
            arch,
            nr,
            arg0,
        ) == RET_KILL_PROCESS,
        arch == AUDIT_ARCH_X86_64 && mode != 3 && nr == NR_SETNS ==> verdict(
            mode,
            list,
            arch,
            nr,
            arg0,
        ) == RET_EPERM,
        arch == AUDIT_ARCH_X86_64 && mode != 3 && nr == NR_CLONE3 ==> verdict(
            mode,
            list,
            arch,
            nr,
            arg0,
        ) == RET_ENOSYS,
        arch == AUDIT_ARCH_X86_64 && mode != 3 && (nr == NR_CLONE || nr == NR_UNSHARE) ==> verdict(
            mode,
            list,
            arch,
            nr,
            arg0,
        ) == if arg0 & CLONE_NEW_ANY != 0 {
            RET_EPERM
        } else {
            RET_ALLOW
        },
        arch == AUDIT_ARCH_X86_64 && mode != 3 && nr < X32_BIT && nr != NR_SETNS && nr != NR_CLONE3
            && nr != NR_CLONE && nr != NR_UNSHARE ==> verdict(mode, list, arch, nr, arg0)
            == if listed_from(list, nr, 0) {
            RET_EPERM
        } else {
            RET_ALLOW
        },
{
    lemma_scan(mode, list, arch, nr, arg0, 0);
    reveal_with_fuel(run, 24);
}

/// The program is well formed and fits `MAX_BPF`.
pub proof fn lemma_wf(mode: u32, list: Seq<u32>)
    requires
        1 <= mode <= 3,
        list.len() <= MAX_FILTER_LIST,
    ensures
        bpf_wf(mode, list),
        plen(mode, list) <= MAX_BPF,
{
    assert forall|k: int| 0 <= k < plen(mode, list) implies {
        let i = #[trigger] insn_at(mode, list, k);
        &&& i.code == BPF_LD_W_ABS || i.code == BPF_JEQ_K || i.code == BPF_JSET_K || i.code
            == BPF_JGE_K || i.code == BPF_RET_K
        &&& (i.code == BPF_JEQ_K || i.code == BPF_JSET_K || i.code == BPF_JGE_K) ==> (k + 1 + (
        i.jt as int) < plen(mode, list)) && (k + 1 + (i.jf as int) < plen(mode, list))
    } by {
        if k >= 4 && k < base(mode) {
            assert(special_at(k - 4).code == BPF_LD_W_ABS || special_at(k - 4).code == BPF_JEQ_K
                || special_at(k - 4).code == BPF_JSET_K || special_at(k - 4).code == BPF_JGE_K
                || special_at(k - 4).code == BPF_RET_K);
        }
    }
}

} // verus!
