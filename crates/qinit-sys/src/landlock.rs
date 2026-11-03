// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Landlock: a ruleset of filesystem rights per path, then `restrict_self`.
use crate::fd::owned;
use crate::{Result, check_long};
use std::ffi::CStr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

/// `LANDLOCK_ACCESS_FS_EXECUTE | READ_FILE | READ_DIR` (bits 0, 2, 3).
pub const LANDLOCK_ACCESS_FS_READ: u64 = (1 << 0) | (1 << 2) | (1 << 3);
/// Every filesystem right of ABI 3: bits 0..=14 (`EXECUTE` to `TRUNCATE`).
pub const LANDLOCK_ACCESS_FS_ALL_V3: u64 = (1 << 15) - 1;
/// `landlock_create_ruleset` flag: return the ABI version (`linux/landlock.h`).
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
/// Rule type `LANDLOCK_RULE_PATH_BENEATH`.
const LANDLOCK_RULE_PATH_BENEATH: libc::c_uint = 1;

/// `struct landlock_ruleset_attr` of ABI 1 to 3 (the filesystem field only).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr` (packed: 12 bytes).
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The Landlock ABI version the kernel offers; `ENOSYS` or `EOPNOTSUPP` when it has none.
pub fn abi() -> Result<u32> {
    // SAFETY: a null attr with size 0 and the version flag queries the ABI only.
    let r = check_long(unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    })?;
    u32::try_from(r).map_err(|_| crate::Errno(libc::EOVERFLOW))
}

/// A ruleset handling the filesystem rights `handled`.
pub fn ruleset(handled: u64) -> Result<OwnedFd> {
    let attr = RulesetAttr {
        handled_access_fs: handled,
    };
    // SAFETY: a readable attr of its exact size and no flags.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            core::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    #[allow(clippy::cast_possible_truncation)] // a descriptor number or -1
    owned(r as libc::c_int)
}

/// The rights that apply to a file: execute, write, read and truncate (`READ_DIR` and the
/// directory-change rights make the kernel refuse a rule on anything but a directory).
const FILE_RIGHTS: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14);

/// Grants `access` beneath `path` in `ruleset`; the path is opened `O_PATH | O_CLOEXEC`. For a
/// path that is not a directory the grant is cut to the rights a file has.
pub fn add_path_rule(ruleset: BorrowedFd<'_>, path: &CStr, access: u64) -> Result<()> {
    // SAFETY: a NUL-terminated path; O_PATH opens without reading.
    let parent = owned(unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) })?;
    let access = if crate::fd::file_type(std::os::fd::AsFd::as_fd(&parent))? == libc::S_IFDIR {
        access
    } else {
        access & FILE_RIGHTS
    };
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: a readable packed attr of the rule type's size, no flags; `parent` stays open
    // for the call.
    check_long(unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const attr,
            0u32,
        )
    })?;
    Ok(())
}

/// `landlock_restrict_self(ruleset, 0)`: needs `no_new_privs` or `CAP_SYS_ADMIN`.
pub fn restrict_self(ruleset: BorrowedFd<'_>) -> Result<()> {
    // SAFETY: integer arguments only.
    check_long(unsafe {
        libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32)
    })?;
    Ok(())
}
