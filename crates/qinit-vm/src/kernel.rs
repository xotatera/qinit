// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pinned guest kernel (plan P5): fetched once, checked against its sha256, configured
//! from `allnoconfig` plus `kernel.config`, built once into qinit's cache.
use crate::supervise::run_logged;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const VERSION: &str = "6.18.59";
pub const URL: &str = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.59.tar.xz";
pub const SHA256: &str = "53a55ac9863a5547e292b8e381d4e4c2240dd1127d5428a7c44dbc550be23963";
pub const FRAGMENT: &str = include_str!("../kernel.config");
/// The variable naming a tarball to use instead of downloading.
pub const TARBALL_ENV: &str = "QINIT_KERNEL_TARBALL";

const FETCH_WITHIN: Duration = Duration::from_mins(30);
const BUILD_WITHIN: Duration = Duration::from_mins(90);

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `$XDG_CACHE_HOME/qinit`, else `$HOME/.cache/qinit` (an empty variable counts as unset).
pub fn cache_root(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf, String> {
    let set = |v: Option<OsString>| v.filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(x) = set(xdg) {
        return Ok(x.join("qinit"));
    }
    set(home).map(|h| h.join(".cache/qinit")).ok_or_else(|| {
        "neither XDG_CACHE_HOME nor HOME is set: qinit's cache has no place".to_string()
    })
}

/// Checks `path` against `expected` (lowercase hex sha256).
pub fn verify(path: &Path, expected: &str) -> Result<(), String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let actual = hex(&h.finalize());
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{}: sha256 {actual} does not match the pinned {expected}",
            path.display()
        ))
    }
}

/// The message when the download failed: how to supply the tarball instead.
#[must_use]
pub fn download_failed(url: &str, why: &str) -> String {
    let file = url.rsplit('/').next().unwrap_or(url);
    format!(
        "could not download {url} ({why}). Download {file} on a machine with network access and set {TARBALL_ENV}=/path/to/{file}; its sha256 must be {SHA256}"
    )
}

/// The message when a tarball fails its checksum (or cannot be read): the same remedy as a
/// failed download, so a corrupt or truncated file is never left unexplained.
#[must_use]
pub fn tarball_refused(why: &str) -> String {
    let file = URL.rsplit('/').next().unwrap_or(URL);
    format!(
        "the kernel tarball was refused: {why}. Download {URL} again (for example with curl -fLO) and set {TARBALL_ENV}=/path/to/{file}; its sha256 must be {SHA256}"
    )
}

/// A tarball the caller supplied (`$QINIT_KERNEL_TARBALL`), checked against the pin.
pub fn supplied_tarball(path: &Path) -> Result<PathBuf, String> {
    verify(path, SHA256).map_err(|e| tarball_refused(&e))?;
    Ok(path.to_path_buf())
}

/// Each `CONFIG_…=…` line of `fragment` that is not a line of `config`.
#[must_use]
pub fn missing_options(fragment: &str, config: &str) -> Vec<String> {
    fragment
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("CONFIG_"))
        .filter(|l| !config.lines().any(|c| c.trim() == *l))
        .map(str::to_string)
        .collect()
}

/// The pinned kernel's bzImage, building it into the cache on first use.
pub fn ensure() -> Result<PathBuf, String> {
    let root = cache_root(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))?;
    let frag_hash = hex(&Sha256::digest(FRAGMENT.as_bytes())[..6]);
    let done = root.join(format!("kernel-{VERSION}-{frag_hash}"));
    let image = done.join("bzImage");
    if image.is_file() {
        return Ok(image);
    }
    std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    let tarball = tarball(&root)?;
    let work = root.join(format!(
        "build-{VERSION}-{frag_hash}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("create {}: {e}", work.display()))?;
    match build_in(&work, &tarball, &done) {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&work);
            Ok(image)
        }
        // Another process built the same kernel first: its result is as good as ours.
        Err(_) if image.is_file() => {
            let _ = std::fs::remove_dir_all(&work);
            Ok(image)
        }
        Err(e) => {
            // The extracted tree is gigabytes; the log stays, and the error names it.
            let _ = std::fs::remove_dir_all(work.join(format!("linux-{VERSION}")));
            let _ = std::fs::remove_dir_all(work.join("done"));
            Err(e)
        }
    }
}

/// Kernel make with ambient cross-build, output and compiler overrides removed.
#[must_use]
pub fn make_command(src: &Path) -> Command {
    let mut make = Command::new("make");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("KBUILD_")
            || name.starts_with("KCONFIG_")
            || name.starts_with("HOST")
            || name.starts_with("LLVM")
            || matches!(
                name.as_ref(),
                "ARCH"
                    | "SUBARCH"
                    | "CROSS_COMPILE"
                    | "CC"
                    | "CXX"
                    | "CPP"
                    | "LD"
                    | "AR"
                    | "AS"
                    | "NM"
                    | "OBJCOPY"
                    | "OBJDUMP"
                    | "STRIP"
                    | "READELF"
                    | "RUSTC"
                    | "RUSTFLAGS"
                    | "KRUSTFLAGS"
                    | "KCFLAGS"
                    | "KAFLAGS"
                    | "CFLAGS"
                    | "CPPFLAGS"
                    | "LDFLAGS"
                    | "MAKEFLAGS"
                    | "MFLAGS"
                    | "MAKEOVERRIDES"
                    | "GNUMAKEFLAGS"
            )
        {
            make.env_remove(key);
        }
    }
    // Explicit removals also make the command's contract inspectable without mutating env.
    for key in ["ARCH", "CROSS_COMPILE", "KBUILD_OUTPUT", "CC", "MAKEFLAGS"] {
        make.env_remove(key);
    }
    make.arg("-C").arg(src);
    make
}

/// Extracts, configures and builds in `work`, then moves the result to `done` whole.
fn build_in(work: &Path, tarball: &Path, done: &Path) -> Result<(), String> {
    let log = work.join("build.log");
    let at = |e: std::io::Error| format!("{e}; log: {}", log.display());
    let mut tar = Command::new("tar");
    tar.arg("-xJf").arg(tarball).arg("-C").arg(work);
    run_logged(tar, &log, BUILD_WITHIN)?;
    let src = work.join(format!("linux-{VERSION}"));
    let fragment = work.join("qinit.config");
    std::fs::write(&fragment, FRAGMENT).map_err(at)?;
    let mut config = make_command(&src);
    config
        .arg("allnoconfig")
        .env("KCONFIG_ALLCONFIG", &fragment);
    run_logged(config, &log, BUILD_WITHIN)?;
    let written = std::fs::read_to_string(src.join(".config")).map_err(at)?;
    let missing = missing_options(FRAGMENT, &written);
    if !missing.is_empty() {
        return Err(format!(
            "the kernel configuration dropped {}; log: {}",
            missing.join(", "),
            log.display()
        ));
    }
    let jobs = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut build = make_command(&src);
    build.arg(format!("-j{jobs}")).arg("bzImage");
    run_logged(build, &log, BUILD_WITHIN)?;
    let staged = work.join("done");
    std::fs::create_dir_all(&staged).map_err(at)?;
    std::fs::copy(src.join("arch/x86/boot/bzImage"), staged.join("bzImage")).map_err(at)?;
    std::fs::copy(src.join(".config"), staged.join("config")).map_err(at)?;
    // The finished directory appears whole or not at all.
    std::fs::rename(&staged, done).map_err(|e| {
        format!(
            "rename into {}: {e}; log: {}",
            done.display(),
            log.display()
        )
    })
}

/// The verified tarball: `$QINIT_KERNEL_TARBALL`, the cached download, or a fresh download.
fn tarball(root: &Path) -> Result<PathBuf, String> {
    if let Some(given) = std::env::var_os(TARBALL_ENV).filter(|v| !v.is_empty()) {
        return supplied_tarball(Path::new(&given));
    }
    let cached = root.join(format!("linux-{VERSION}.tar.xz"));
    if cached.is_file() && verify(&cached, SHA256).is_ok() {
        return Ok(cached);
    }
    let partial = root.join(format!(
        "linux-{VERSION}.tar.xz.part-{}",
        std::process::id()
    ));
    let mut curl = Command::new("curl");
    curl.args(["-fL", "--retry", "3", "-o"])
        .arg(&partial)
        .arg(URL);
    let log = root.join("download.log");
    if let Err(e) = run_logged(curl, &log, FETCH_WITHIN) {
        let _ = std::fs::remove_file(&partial);
        return Err(download_failed(URL, &e));
    }
    if let Err(e) = verify(&partial, SHA256) {
        let _ = std::fs::remove_file(&partial);
        return Err(tarball_refused(&format!("the download is corrupt ({e})")));
    }
    std::fs::rename(&partial, &cached).map_err(|e| e.to_string())?;
    Ok(cached)
}
