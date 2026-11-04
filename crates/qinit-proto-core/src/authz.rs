// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: MPL-2.0
//! Who may ask for what. One function decides every request; it is where a privilege authority
//! plugs in later.
use vstd::prelude::*;

verus! {

/// A request kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Status,
    List,
    Change,
    Launch,
    Refresh,
    Shutdown,
    Run,
}

/// The identity of the peer that sent a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerId {
    /// The peer's user id, from `SO_PEERCRED` at connect.
    pub uid: u32,
}

/// Whether `peer` may do `op`: anyone may read status and the list; everything else is root's.
#[must_use]
pub fn authorized(op: Op, peer: PeerId) -> (r: bool)
    ensures
        r == (peer.uid == 0 || op == Op::Status || op == Op::List),
{
    peer.uid == 0 || matches!(op, Op::Status | Op::List)
}

/// The operation a request message type asks for, or `None` for a reply type or an unknown one.
#[must_use]
pub fn op_of_type(t: u32) -> (r: Option<Op>)
    ensures
        t == 1 ==> r == Some(Op::Status),
        t == 2 ==> r == Some(Op::List),
        t == 3 ==> r == Some(Op::Change),
        t == 4 ==> r == Some(Op::Launch),
        t == 5 ==> r == Some(Op::Refresh),
        t == 6 ==> r == Some(Op::Shutdown),
        t == 7 ==> r == Some(Op::Run),
        (t == 0 || t > 7) ==> r is None,
{
    if t == 1 {
        Some(Op::Status)
    } else if t == 2 {
        Some(Op::List)
    } else if t == 3 {
        Some(Op::Change)
    } else if t == 4 {
        Some(Op::Launch)
    } else if t == 5 {
        Some(Op::Refresh)
    } else if t == 6 {
        Some(Op::Shutdown)
    } else if t == 7 {
        Some(Op::Run)
    } else {
        None
    }
}

} // verus!
