// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! The total decoder: `check` returns `Ok` only for an [`accepted`] message, and the in-place
//! accessors that are in bounds for any accepted message.
#[allow(clippy::wildcard_imports)] // the layout constants, used throughout
use crate::layout::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::lists::*;
#[allow(unused_imports, clippy::wildcard_imports)] // spec-only items; Verus erases them
use crate::spec::*;
use crate::utf8::utf8_ok;
use vstd::prelude::*;

verus! {

/// Why a message is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Too short or too long, a bad magic, or a length that disagrees with the buffer.
    Header = 1,
    /// A version this decoder does not speak.
    Version = 2,
    /// A message type the format does not have.
    Type = 3,
    /// A string reference leaves the message or enters the record, is not UTF-8, or a list has
    /// an empty element.
    Pool = 4,
    /// An enum word is out of range.
    Enum = 5,
    /// Fields contradict each other or break a content rule.
    Consistency = 6,
    /// The descriptors received, declared and required disagree.
    FdCount = 7,
}

/// Little-endian word `i` of `b`.
#[must_use]
#[allow(clippy::cast_lossless)]  // `u32::from` is not available inside `verus!`
pub fn word(b: &[u8], i: usize) -> (w: u32)
    requires
        i < 0x4000_0000,
        4 * i + 4 <= b@.len(),
    ensures
        w == spec_word(b@, i as int),
{
    (b[4 * i] as u32) | ((b[4 * i + 1] as u32) << 8) | ((b[4 * i + 2] as u32) << 16) | ((b[4 * i
        + 3] as u32) << 24)
}

/// Record word `w`.
fn rword(b: &[u8], w: usize) -> (v: u32)
    requires
        w < 0x1000,
        4 * (HEADER_WORDS + w + 1) <= b@.len(),
    ensures
        v as int == rw(b@, w as int),
{
    word(b, HEADER_WORDS + w)
}

/// Word `w` of list entry `i` of a list page.
fn eword(b: &[u8], i: usize, w: usize) -> (v: u32)
    requires
        shape_ok(b@),
        mtype(b@) == T_LIST_PAGE,
        i < rw(b@, LP_COUNT as int),
        w < ENTRY_WORDS,
    ensures
        v as int == ew(b@, i as int, w as int),
{
    word(b, HEADER_WORDS + LP_FIXED_WORDS + ENTRY_WORDS * i + w)
}

fn check_header(b: &[u8]) -> (r: Result<(), DecodeError>)
    ensures
        r is Ok ==> header_ok(b@),
{
    if b.len() < 4 * HEADER_WORDS || b.len() > MAX_MESSAGE {
        return Err(DecodeError::Header);
    }
    if word(b, H_MAGIC) != QCP_MAGIC {
        return Err(DecodeError::Header);
    }
    if word(b, H_VERSION) != QCP_VERSION {
        return Err(DecodeError::Version);
    }
    if word(b, H_TOTAL_LEN) as usize != b.len() {
        return Err(DecodeError::Header);
    }
    Ok(())
}

/// The header, a known type and the record region inside the message.
fn check_shape(b: &[u8]) -> (r: Result<u32, DecodeError>)
    ensures
        r is Ok ==> shape_ok(b@) && r.unwrap() as int == mtype(b@),
{
    check_header(b)?;
    let t = word(b, H_TYPE);
    if !known_type(t) {
        return Err(DecodeError::Type);
    }
    let n = record_words(t);
    if b.len() < 4 * (HEADER_WORDS + n) {
        return Err(DecodeError::Header);
    }
    if t == T_LIST_PAGE {
        let count = rword(b, LP_COUNT) as usize;
        if count > MAX_LIST_ENTRIES {
            return Err(DecodeError::Consistency);
        }
        if b.len() < 4 * (HEADER_WORDS + LP_FIXED_WORDS + ENTRY_WORDS * count) {
            return Err(DecodeError::Header);
        }
    }
    Ok(t)
}

/// Where the string pool begins.
fn record_end(b: &[u8], t: u32) -> (e: usize)
    requires
        shape_ok(b@),
        t as int == mtype(b@),
    ensures
        e as int == rec_end(b@),
{
    if t == T_LIST_PAGE {
        4 * (HEADER_WORDS + LP_FIXED_WORDS + ENTRY_WORDS * (rword(b, LP_COUNT) as usize))
    } else {
        4 * (HEADER_WORDS + record_words(t))
    }
}

/// Checks one string reference against the end of the record region `rend`.
fn sref_ok(b: &[u8], rend: usize, off: u32, len: u32) -> (r: Result<(), DecodeError>)
    requires
        rend as int == rec_end(b@),
    ensures
        r is Ok ==> sref(b@, off as int, len as int) && off as int + len as int <= b@.len(),
{
    let o = off as usize;
    let l = len as usize;
    if o < rend || o > b.len() || l > b.len() - o {
        return Err(DecodeError::Pool);
    }
    if !utf8_ok(b, o, o + l) {
        return Err(DecodeError::Pool);
    }
    Ok(())
}

/// Checks a list reference: a string reference whose bytes are NUL-separated non-empty elements.
fn lref_ok(b: &[u8], rend: usize, off: u32, len: u32) -> (r: Result<(), DecodeError>)
    requires
        b@.len() <= MAX_MESSAGE,
        rend as int == rec_end(b@),
    ensures
        r is Ok ==> lref(b@, off as int, len as int) && off as int + len as int <= b@.len(),
{
    sref_ok(b, rend, off, len)?;
    let o = off as usize;
    let l = len as usize;
    if !nul_list_ok(b, o, o + l) {
        return Err(DecodeError::Pool);
    }
    Ok(())
}

fn check_list_refs(b: &[u8], rend: usize) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        mtype(b@) == T_LIST_PAGE,
        rend as int == rec_end(b@),
    ensures
        r is Ok ==> refs_ok(b@),
{
    let count = rword(b, LP_COUNT) as usize;
    let mut i: usize = 0;
    while i < count
        invariant
            shape_ok(b@),
            mtype(b@) == T_LIST_PAGE,
            rend as int == rec_end(b@),
            count as int == rw(b@, LP_COUNT as int),
            count <= MAX_LIST_ENTRIES,
            i <= count,
            forall|j: int|
                0 <= j < i ==> #[trigger] sref(
                    b@,
                    ew(b@, j, EN_NAME_OFF as int),
                    ew(b@, j, EN_NAME_LEN as int),
                ),
        decreases count - i,
    {
        sref_ok(b, rend, eword(b, i, EN_NAME_OFF), eword(b, i, EN_NAME_LEN))?;
        i += 1;
    }
    Ok(())
}

fn check_refs(b: &[u8], t: u32) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        t as int == mtype(b@),
    ensures
        r is Ok ==> refs_ok(b@),
{
    let rend = record_end(b, t);
    if t == T_STATUS {
        sref_ok(b, rend, rword(b, ST_TARGET_OFF), rword(b, ST_TARGET_LEN))
    } else if t == T_CHANGE {
        sref_ok(b, rend, rword(b, CH_TARGET_OFF), rword(b, CH_TARGET_LEN))
    } else if t == T_LAUNCH {
        sref_ok(b, rend, rword(b, LA_FRAME_OFF), rword(b, LA_FRAME_LEN))?;
        lref_ok(b, rend, rword(b, LA_ARGV_OFF), rword(b, LA_ARGV_LEN))?;
        lref_ok(b, rend, rword(b, LA_ENV_OFF), rword(b, LA_ENV_LEN))
    } else if t == T_NODE_STATUS {
        sref_ok(b, rend, rword(b, NS_NAME_OFF), rword(b, NS_NAME_LEN))?;
        sref_ok(b, rend, rword(b, NS_TARGET_OFF), rword(b, NS_TARGET_LEN))
    } else if t == T_INSTANCE_STATUS {
        sref_ok(b, rend, rword(b, IS_FRAME_OFF), rword(b, IS_FRAME_LEN))
    } else if t == T_LIST_PAGE {
        check_list_refs(b, rend)
    } else {
        Ok(())
    }
}

fn check_list_enums(b: &[u8]) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        mtype(b@) == T_LIST_PAGE,
    ensures
        r is Ok ==> enums_ok(b@),
{
    let count = rword(b, LP_COUNT) as usize;
    let mut i: usize = 0;
    while i < count
        invariant
            shape_ok(b@),
            mtype(b@) == T_LIST_PAGE,
            count as int == rw(b@, LP_COUNT as int),
            count <= MAX_LIST_ENTRIES,
            i <= count,
            forall|j: int| 0 <= j < i ==> #[trigger] entry_enums_ok(b@, j),
        decreases count - i,
    {
        if eword(b, i, EN_KIND) > 2 || eword(b, i, EN_STATE) > 6 {
            return Err(DecodeError::Enum);
        }
        i += 1;
    }
    Ok(())
}

#[allow(clippy::manual_range_contains, clippy::collapsible_else_if)]  // `contains` has no Verus spec; the chain mirrors `enums_ok`
fn check_enums(b: &[u8], t: u32) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        t as int == mtype(b@),
    ensures
        r is Ok ==> enums_ok(b@),
{
    let bad = Err(DecodeError::Enum);
    if t == T_LIST {
        if rword(b, LI_KIND) > 3 {
            return bad;
        }
    } else if t == T_CHANGE {
        if rword(b, CH_ACTION) > 5 || rword(b, CH_SETTLED) > 1 {
            return bad;
        }
    } else if t == T_LAUNCH {
        if rword(b, LA_FD_ROLES) > 7 || rword(b, LA_FLAGS) > FLAG_PIDFD {
            return bad;
        }
    } else if t == T_REFRESH {
        if rword(b, RF_SETTLED) > 1 {
            return bad;
        }
    } else if t == T_SHUTDOWN {
        if rword(b, SH_MODE) > 2 || rword(b, SH_SETTLED) > 1 {
            return bad;
        }
    } else if t == T_ERROR {
        let code = rword(b, ER_CODE);
        if code < 1 || code > 12 {
            return bad;
        }
    } else if t == T_NODE_STATUS {
        if rword(b, NS_KIND) > 2 || rword(b, NS_STATE) > 6 {
            return bad;
        }
    } else if t == T_INSTANCE_STATUS {
        let state = rword(b, IS_STATE);
        if state < 2 || state > 5 || rword(b, IS_HAS_STATUS) > 1 {
            return bad;
        }
    } else if t == T_LIST_PAGE {
        return check_list_enums(b);
    } else if (t == T_SETTLED || t == T_PENDING || t == T_SUPERSEDED) && rword(b, SW_STATE) > 6 {
        return bad;
    }
    Ok(())
}

#[allow(clippy::manual_range_contains)]  // `contains` has no Verus spec
fn wait_ok_exec(settled: u32, wait_ms: u32) -> (r: bool)
    ensures
        r == wait_ok(settled as int, wait_ms as int),
{
    if settled == 1 {
        1 <= wait_ms && wait_ms <= MAX_WAIT_MS
    } else {
        wait_ms == 0
    }
}

fn name_len_exec(len: u32) -> (r: bool)
    ensures
        r == name_len_ok(len as int),
{
    1 <= len && len as usize <= MAX_NAME_LEN
}

fn target_len_exec(len: u32) -> (r: bool)
    ensures
        r == target_len_ok(len as int),
{
    1 <= len && len as usize <= MAX_TARGET_LEN
}

fn check_list_content(b: &[u8]) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        mtype(b@) == T_LIST_PAGE,
    ensures
        r is Ok ==> content_ok(b@),
{
    let count = rword(b, LP_COUNT) as usize;
    let mut i: usize = 0;
    while i < count
        invariant
            shape_ok(b@),
            mtype(b@) == T_LIST_PAGE,
            count as int == rw(b@, LP_COUNT as int),
            count <= MAX_LIST_ENTRIES,
            i <= count,
            forall|j: int| 0 <= j < i ==> #[trigger] entry_content_ok(b@, j),
        decreases count - i,
    {
        if !name_len_exec(eword(b, i, EN_NAME_LEN)) {
            return Err(DecodeError::Consistency);
        }
        i += 1;
    }
    Ok(())
}

/// The pool bytes `off..off + len` of a message whose references are established.
fn pool_bytes(b: &[u8], off: u32, len: u32) -> (s: &[u8])
    requires
        b@.len() <= MAX_MESSAGE,
        sref(b@, off as int, len as int),
    ensures
        s@ == mstr(b@, off as int, len as int),
{
    assert(off as int + len as int <= b@.len());
    vstd::slice::slice_subrange(b, off as usize, off as usize + len as usize)
}

fn check_launch_content(b: &[u8]) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        mtype(b@) == T_LAUNCH,
        refs_ok(b@),
    ensures
        r is Ok ==> content_ok(b@),
{
    let bad = Err(DecodeError::Consistency);
    if !name_len_exec(rword(b, LA_FRAME_LEN)) {
        return bad;
    }
    if !wait_ok_exec(1, rword(b, LA_WAIT_MS)) {
        return bad;
    }
    let argv = pool_bytes(b, rword(b, LA_ARGV_OFF), rword(b, LA_ARGV_LEN));
    if count_elements(argv) > MAX_ARGV_TAIL {
        return bad;
    }
    let env = pool_bytes(b, rword(b, LA_ENV_OFF), rword(b, LA_ENV_LEN));
    if !env_elements_ok(env) || count_elements(env) > MAX_ENV_ADD {
        return bad;
    }
    Ok(())
}

fn check_content(b: &[u8], t: u32) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        t as int == mtype(b@),
        refs_ok(b@),
    ensures
        r is Ok ==> content_ok(b@),
{
    let bad = Err(DecodeError::Consistency);
    if t == T_STATUS {
        if !target_len_exec(rword(b, ST_TARGET_LEN)) {
            return bad;
        }
    } else if t == T_CHANGE {
        if !target_len_exec(rword(b, CH_TARGET_LEN)) || !wait_ok_exec(
            rword(b, CH_SETTLED),
            rword(b, CH_WAIT_MS),
        ) {
            return bad;
        }
    } else if t == T_LAUNCH {
        return check_launch_content(b);
    } else if t == T_REFRESH {
        if !wait_ok_exec(rword(b, RF_SETTLED), rword(b, RF_WAIT_MS)) {
            return bad;
        }
    } else if t == T_SHUTDOWN {
        if !wait_ok_exec(rword(b, SH_SETTLED), rword(b, SH_WAIT_MS)) {
            return bad;
        }
    } else if t == T_NODE_STATUS {
        let group = rword(b, NS_GROUP);
        let tlen = rword(b, NS_TARGET_LEN);
        if !name_len_exec(rword(b, NS_NAME_LEN)) || (group == NONE && tlen != 0) || (group != NONE
            && !name_len_exec(tlen)) {
            return bad;
        }
    } else if t == T_INSTANCE_STATUS {
        let has = rword(b, IS_HAS_STATUS);
        if !name_len_exec(rword(b, IS_FRAME_LEN)) || ((has == 1) != (rword(b, IS_STATE) == 4)) || (
        has == 0 && rword(b, IS_STATUS) != 0) {
            return bad;
        }
    } else if t == T_LIST_PAGE {
        return check_list_content(b);
    }
    Ok(())
}

/// The descriptors a launch carries for `roles` (0 to 7).
fn roles_count(roles: u32) -> (n: u32)
    requires
        roles <= 7,
    ensures
        n as int == spec_roles_count(roles as int),
{
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

#[allow(clippy::bool_to_int_with_if)]  // the branches mirror `required_fds`
fn check_fds(b: &[u8], t: u32, received: usize) -> (r: Result<(), DecodeError>)
    requires
        shape_ok(b@),
        t as int == mtype(b@),
        enums_ok(b@),
    ensures
        r is Ok ==> fds_ok(b@, received as int),
{
    let declared = word(b, H_FD_COUNT);
    let required = if t == T_LAUNCH {
        roles_count(rword(b, LA_FD_ROLES))
    } else if t == T_REFRESH {
        1
    } else {
        0
    };
    if declared as usize != received {
        return Err(DecodeError::FdCount);
    }
    if t == T_LAUNCHED {
        if declared > 1 {
            return Err(DecodeError::FdCount);
        }
    } else if declared != required {
        return Err(DecodeError::FdCount);
    }
    Ok(())
}

/// Checks that `b`, which arrived with `received` descriptors, is a message of the format.
///
/// # Errors
/// The first rule the message breaks, checked in the order header, version, type, record,
/// string references, enums, content, descriptors.
pub fn check(b: &[u8], received: usize) -> (r: Result<(), DecodeError>)
    ensures
        r is Ok ==> accepted(b@, received as int),
{
    let t = check_shape(b)?;
    check_refs(b, t)?;
    check_enums(b, t)?;
    check_content(b, t)?;
    check_fds(b, t, received)?;
    Ok(())
}

/// The message type of an accepted message.
#[must_use]
pub fn message_type(b: &[u8]) -> (t: u32)
    requires
        shape_ok(b@),
    ensures
        t as int == mtype(b@),
{
    word(b, H_TYPE)
}

/// Record word `w` of an accepted message.
#[must_use]
pub fn rec(b: &[u8], w: usize) -> (v: u32)
    requires
        shape_ok(b@),
        w < spec_record_words(mtype(b@)),
    ensures
        v as int == rw(b@, w as int),
{
    rword(b, w)
}

/// Word `w` of entry `i` of an accepted list page.
#[must_use]
pub fn entry(b: &[u8], i: usize, w: usize) -> (v: u32)
    requires
        shape_ok(b@),
        mtype(b@) == T_LIST_PAGE,
        i < rw(b@, LP_COUNT as int),
        w < ENTRY_WORDS,
    ensures
        v as int == ew(b@, i as int, w as int),
{
    eword(b, i, w)
}

/// The string `off..off + len` of an accepted message (one its record names).
#[must_use]
pub fn string(b: &[u8], off: u32, len: u32) -> (s: &[u8])
    requires
        b@.len() <= MAX_MESSAGE,
        sref(b@, off as int, len as int),
    ensures
        s@ == mstr(b@, off as int, len as int),
{
    pool_bytes(b, off, len)
}

} // verus!
