// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! What `decode` accepts, as spec functions over the message bytes: the header, the record,
//! every string reference, the enums, the content rules and the descriptor count.
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::layout::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::lists::*;
use vstd::prelude::*;

verus! {

/// Little-endian word `i` of `buf`.
pub open spec fn spec_word(buf: Seq<u8>, i: int) -> u32 {
    ((buf[4 * i] as u32) | ((buf[4 * i + 1] as u32) << 8u32) | ((buf[4 * i + 2] as u32) << 16u32)
        | ((buf[4 * i + 3] as u32) << 24u32))
}

/// Word `i` of the message.
pub open spec fn hw(b: Seq<u8>, i: int) -> int {
    spec_word(b, i) as int
}

/// Record word `w`.
pub open spec fn rw(b: Seq<u8>, w: int) -> int {
    hw(b, HEADER_WORDS as int + w)
}

/// The message type.
pub open spec fn mtype(b: Seq<u8>) -> int {
    hw(b, H_TYPE as int)
}

/// Word `w` of list entry `i`.
pub open spec fn ew(b: Seq<u8>, i: int, w: int) -> int {
    hw(b, HEADER_WORDS as int + LP_FIXED_WORDS as int + ENTRY_WORDS as int * i + w)
}

/// The header: length within `MAX_MESSAGE`, magic, version, total length equal to the buffer.
pub open spec fn header_ok(b: Seq<u8>) -> bool {
    &&& 4 * HEADER_WORDS <= b.len() <= MAX_MESSAGE
    &&& hw(b, H_MAGIC as int) == QCP_MAGIC
    &&& hw(b, H_VERSION as int) == QCP_VERSION
    &&& hw(b, H_TOTAL_LEN as int) == b.len()
}

/// The type is one of the format.
pub open spec fn type_ok(b: Seq<u8>) -> bool {
    spec_known_type(mtype(b))
}

/// The fixed record of the type is inside the message.
pub open spec fn fixed_fits(b: Seq<u8>) -> bool {
    4 * (HEADER_WORDS + spec_record_words(mtype(b))) <= b.len()
}

/// A list page holds at most `MAX_LIST_ENTRIES` entries.
pub open spec fn count_ok(b: Seq<u8>) -> bool {
    mtype(b) == T_LIST_PAGE ==> rw(b, LP_COUNT as int) <= MAX_LIST_ENTRIES
}

/// Where the record region ends and the string pool begins, in bytes.
pub open spec fn rec_end(b: Seq<u8>) -> int {
    4 * (HEADER_WORDS + spec_record_words(mtype(b)) + if mtype(b) == T_LIST_PAGE {
        ENTRY_WORDS as int * rw(b, LP_COUNT as int)
    } else {
        0
    })
}

/// The whole record region (the fixed record and a list page's entries) is inside the message.
pub open spec fn fits(b: Seq<u8>) -> bool {
    rec_end(b) <= b.len()
}

/// A string reference: after the record region, inside the message, valid UTF-8.
pub open spec fn sref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& rec_end(b) <= off
    &&& 0 <= len
    &&& off + len <= b.len()
    &&& vstd::utf8::valid_utf8(b.subrange(off, off + len))
}

/// A list reference: a string reference whose bytes are a [`nul_list`].
pub open spec fn lref(b: Seq<u8>, off: int, len: int) -> bool {
    &&& sref(b, off, len)
    &&& nul_list(b.subrange(off, off + len))
}

/// The string `off..off + len` of the message.
pub open spec fn mstr(b: Seq<u8>, off: int, len: int) -> Seq<u8> {
    b.subrange(off, off + len)
}

/// Every string reference of the record is inside the message and valid, and every list is a
/// [`nul_list`].
pub open spec fn refs_ok(b: Seq<u8>) -> bool {
    let t = mtype(b);
    if t == T_STATUS {
        sref(b, rw(b, ST_TARGET_OFF as int), rw(b, ST_TARGET_LEN as int))
    } else if t == T_CHANGE {
        sref(b, rw(b, CH_TARGET_OFF as int), rw(b, CH_TARGET_LEN as int))
    } else if t == T_LAUNCH {
        &&& sref(b, rw(b, LA_FRAME_OFF as int), rw(b, LA_FRAME_LEN as int))
        &&& lref(b, rw(b, LA_ARGV_OFF as int), rw(b, LA_ARGV_LEN as int))
        &&& lref(b, rw(b, LA_ENV_OFF as int), rw(b, LA_ENV_LEN as int))
    } else if t == T_NODE_STATUS {
        &&& sref(b, rw(b, NS_NAME_OFF as int), rw(b, NS_NAME_LEN as int))
        &&& sref(b, rw(b, NS_TARGET_OFF as int), rw(b, NS_TARGET_LEN as int))
    } else if t == T_INSTANCE_STATUS {
        sref(b, rw(b, IS_FRAME_OFF as int), rw(b, IS_FRAME_LEN as int))
    } else if t == T_LIST_PAGE {
        forall|i: int|
            0 <= i < rw(b, LP_COUNT as int) ==> #[trigger] sref(
                b,
                ew(b, i, EN_NAME_OFF as int),
                ew(b, i, EN_NAME_LEN as int),
            )
    } else {
        true
    }
}

/// One entry of a list page has its enums in range.
pub open spec fn entry_enums_ok(b: Seq<u8>, i: int) -> bool {
    &&& ew(b, i, EN_KIND as int) <= 2
    &&& ew(b, i, EN_STATE as int) <= 6
}

/// Every enum word of the record is in range.
pub open spec fn enums_ok(b: Seq<u8>) -> bool {
    let t = mtype(b);
    if t == T_LIST {
        rw(b, LI_KIND as int) <= 3
    } else if t == T_CHANGE {
        &&& rw(b, CH_ACTION as int) <= 5
        &&& rw(b, CH_SETTLED as int) <= 1
    } else if t == T_LAUNCH {
        &&& rw(b, LA_FD_ROLES as int) <= 7
        &&& rw(b, LA_FLAGS as int) <= FLAG_PIDFD as int
    } else if t == T_REFRESH {
        rw(b, RF_SETTLED as int) <= 1
    } else if t == T_SHUTDOWN {
        &&& rw(b, SH_MODE as int) <= 2
        &&& rw(b, SH_SETTLED as int) <= 1
    } else if t == T_ERROR {
        1 <= rw(b, ER_CODE as int) <= 12
    } else if t == T_NODE_STATUS {
        &&& rw(b, NS_KIND as int) <= 2
        &&& rw(b, NS_STATE as int) <= 6
    } else if t == T_INSTANCE_STATUS {
        &&& 2 <= rw(b, IS_STATE as int) <= 5
        &&& rw(b, IS_HAS_STATUS as int) <= 1
    } else if t == T_LIST_PAGE {
        forall|i: int| 0 <= i < rw(b, LP_COUNT as int) ==> #[trigger] entry_enums_ok(b, i)
    } else if t == T_SETTLED || t == T_PENDING || t == T_SUPERSEDED {
        rw(b, SW_STATE as int) <= 6
    } else {
        true
    }
}

/// `settled` and `wait_ms` agree: a settled request waits 1 to `MAX_WAIT_MS`, another waits 0.
pub open spec fn wait_ok(settled: int, wait_ms: int) -> bool {
    if settled == 1 {
        1 <= wait_ms <= MAX_WAIT_MS
    } else {
        wait_ms == 0
    }
}

/// A name of 1 to `MAX_NAME_LEN` bytes.
pub open spec fn name_len_ok(len: int) -> bool {
    1 <= len <= MAX_NAME_LEN
}

/// A target of 1 to `MAX_TARGET_LEN` bytes.
pub open spec fn target_len_ok(len: int) -> bool {
    1 <= len <= MAX_TARGET_LEN
}

/// One entry of a list page has a name of the right length.
pub open spec fn entry_content_ok(b: Seq<u8>, i: int) -> bool {
    name_len_ok(ew(b, i, EN_NAME_LEN as int))
}

/// The content rules of the record: string lengths, list caps and entries, the wait rule, and
/// the fields that agree with each other.
pub open spec fn content_ok(b: Seq<u8>) -> bool {
    let t = mtype(b);
    if t == T_STATUS {
        target_len_ok(rw(b, ST_TARGET_LEN as int))
    } else if t == T_CHANGE {
        &&& target_len_ok(rw(b, CH_TARGET_LEN as int))
        &&& wait_ok(rw(b, CH_SETTLED as int), rw(b, CH_WAIT_MS as int))
    } else if t == T_LAUNCH {
        let argv = mstr(b, rw(b, LA_ARGV_OFF as int), rw(b, LA_ARGV_LEN as int));
        let env = mstr(b, rw(b, LA_ENV_OFF as int), rw(b, LA_ENV_LEN as int));
        &&& name_len_ok(rw(b, LA_FRAME_LEN as int))
        &&& elems(argv) <= MAX_ARGV_TAIL
        &&& env_list_ok(env)
        &&& elems(env) <= MAX_ENV_ADD
        &&& wait_ok(1, rw(b, LA_WAIT_MS as int))
    } else if t == T_REFRESH {
        wait_ok(rw(b, RF_SETTLED as int), rw(b, RF_WAIT_MS as int))
    } else if t == T_SHUTDOWN {
        wait_ok(rw(b, SH_SETTLED as int), rw(b, SH_WAIT_MS as int))
    } else if t == T_NODE_STATUS {
        &&& name_len_ok(rw(b, NS_NAME_LEN as int))
        &&& (rw(b, NS_GROUP as int) == NONE ==> rw(b, NS_TARGET_LEN as int) == 0)
        &&& (rw(b, NS_GROUP as int) != NONE ==> name_len_ok(rw(b, NS_TARGET_LEN as int)))
    } else if t == T_INSTANCE_STATUS {
        &&& name_len_ok(rw(b, IS_FRAME_LEN as int))
        &&& ((rw(b, IS_HAS_STATUS as int) == 1) == (rw(b, IS_STATE as int) == 4))
        &&& (rw(b, IS_HAS_STATUS as int) == 0 ==> rw(b, IS_STATUS as int) == 0)
    } else if t == T_LIST_PAGE {
        forall|i: int| 0 <= i < rw(b, LP_COUNT as int) ==> #[trigger] entry_content_ok(b, i)
    } else {
        true
    }
}

/// The descriptors a message of this record must carry: one per role of a launch, one for a
/// refresh, none otherwise.
pub open spec fn spec_roles_count(roles: int) -> int {
    if roles == 0 {
        0
    } else if roles == 1 || roles == 2 || roles == 4 {
        1
    } else if roles == 7 {
        3
    } else {
        2
    }
}

/// The descriptor count the record requires.
pub open spec fn required_fds(b: Seq<u8>) -> int {
    let t = mtype(b);
    if t == T_LAUNCH {
        spec_roles_count(rw(b, LA_FD_ROLES as int))
    } else if t == T_REFRESH {
        1
    } else {
        0
    }
}

/// The header's descriptor count is the number received and the number the record requires. A
/// `Launched` reply carries a pidfd or none, so for it the count is 0 or 1.
pub open spec fn fds_ok(b: Seq<u8>, received: int) -> bool {
    &&& hw(b, H_FD_COUNT as int) == received
    &&& if mtype(b) == T_LAUNCHED {
        hw(b, H_FD_COUNT as int) <= 1
    } else {
        hw(b, H_FD_COUNT as int) == required_fds(b)
    }
}

/// The shape of a message: the header, a known type, and the whole record region inside it.
pub open spec fn shape_ok(b: Seq<u8>) -> bool {
    &&& header_ok(b)
    &&& type_ok(b)
    &&& fixed_fits(b)
    &&& count_ok(b)
    &&& fits(b)
}

/// A message `decode` accepts, given `received` descriptors with it.
pub open spec fn accepted(b: Seq<u8>, received: int) -> bool {
    &&& shape_ok(b)
    &&& refs_ok(b)
    &&& enums_ok(b)
    &&& content_ok(b)
    &&& fds_ok(b, received)
}

} // verus!
