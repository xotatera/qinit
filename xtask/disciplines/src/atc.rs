// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The host scheduler atc: whether it answers, the names its profiles are
//! kept under, the `atc run` prefix for cargo gates, and what its own exit
//! codes mean. Pure but for `detect`, which runs `atc status` once per process.
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Whether steps can be reserved through atc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Atc {
    Available,
    /// Why not, as printed in `atc: not available (<why>)`.
    Absent(String),
}

/// Declares no GPU use: undeclared, atc's first run of a name reserves the
/// whole GPU and 4G of VRAM, which caps how many steps run at once.
pub const NO_GPU: [&str; 4] = ["--gpu-min", "0", "--vram-min", "0"];

/// How a step runs: `atc run --name <repo>/…`, or unreserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reserve {
    Atc { repo: String },
    None,
}

/// atc on `path` whose `status` (run by `status`, which returns the exit
/// code, `None` on a signal) exits 0.
pub fn probe(path: Option<&OsStr>, status: &dyn Fn(&Path) -> std::io::Result<Option<i32>>) -> Atc {
    let Some(bin) = path.and_then(|p| crate::tools::resolve_in(p, "atc")) else {
        return Atc::Absent("not on PATH".to_string());
    };
    match status(&bin) {
        Ok(Some(0)) => Atc::Available,
        Ok(Some(c)) => Atc::Absent(format!("`atc status` exited {c}")),
        Ok(None) => Atc::Absent("`atc status` was killed by a signal".to_string()),
        Err(e) => Atc::Absent(format!("cannot run `atc status`: {e}")),
    }
}

/// `probe` on this process's PATH, once; the first call prints
/// `atc: not available (<why>)` when it is absent.
pub fn detect() -> &'static Atc {
    static ATC: OnceLock<Atc> = OnceLock::new();
    ATC.get_or_init(|| {
        let atc = probe(std::env::var_os("PATH").as_deref(), &|bin| {
            Command::new(bin)
                .arg("status")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.code())
        });
        if let Atc::Absent(why) = &atc {
            eprintln!("atc: not available ({why})");
        }
        atc
    })
}

/// The repository's name: its main worktree's directory, from git's common
/// dir, so every linked worktree shares the profiles; else the file name of
/// the canonicalized root. Profiles are host-wide, and `test` in one
/// repository is not the work of `test` in another.
#[must_use]
pub fn repo_name(root: &Path) -> String {
    let common = Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .current_dir(root)
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    name_of(common.as_deref(), root)
}

/// `repo_name` from git's common dir: `<main>/.git` gives `<main>`'s name, a
/// bare `<name>.git` gives `<name>`; without one, the root's own name.
#[must_use]
pub fn name_of(common: Option<&Path>, root: &Path) -> String {
    let file = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned());
    let from_git = common.and_then(|c| match file(c).as_deref() {
        Some(".git") => c.parent().and_then(file),
        Some(n) => Some(n.strip_suffix(".git").unwrap_or(n).to_string()),
        None => None,
    });
    from_git.unwrap_or_else(|| {
        let base = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        file(&base).unwrap_or_else(|| "repo".to_string())
    })
}

/// Set (non-empty, not `0`) by a caller whose own clock waits on the proof
/// jobs, such as the xtask suite's real-atc sections: atc freezes a job
/// alone, while that caller's deadlines run on, so every proof job then runs
/// under `--never-pause` (plan `2026-10-13-pause-proof.md` R3).
pub const NEVER_PAUSE_ENV: &str = "DISCIPLINES_ATC_NEVER_PAUSE";

/// Whether [`NEVER_PAUSE_ENV`]'s `value` asks for `--never-pause`.
#[must_use]
pub fn never_pause(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

/// `Reserve::Atc` named for `root` when atc answers, else `Reserve::None`.
#[must_use]
pub fn reserve(root: &Path) -> Reserve {
    match detect() {
        Atc::Available => Reserve::Atc {
            repo: repo_name(root),
        },
        Atc::Absent(_) => Reserve::None,
    }
}

/// A cargo gate's argv, under `atc run --name <repo>/gate:<name> --` when
/// reserved; declaring no GPU use unless the repository's gates use it (`gpu`).
#[must_use]
pub fn wrap(reserve: &Reserve, name: &str, gpu: bool, argv: Vec<String>) -> Vec<String> {
    match reserve {
        Reserve::None => argv,
        Reserve::Atc { repo } => {
            let mut v = ["atc", "run", "--name"].map(String::from).to_vec();
            v.push(format!("{repo}/gate:{name}"));
            if !gpu {
                v.extend(NO_GPU.map(String::from));
            }
            v.push("--".to_string());
            v.extend(argv);
            v
        }
    }
}

/// What atc's own exit `code` means under `atc run`; `None` for every other
/// code, which is the command's. `cap` is the `--ram-max` as passed, `held`
/// whether this process already runs inside an `atc run`.
#[must_use]
pub fn exit_message(code: i32, cap: Option<&str>, held: bool) -> Option<String> {
    let refused = "atc refused the reservation (see atc's line above)";
    Some(match code {
        64 => "atc usage error (see atc's line above)".to_string(),
        69 => "atc daemon unavailable, or its protocol changed (atc was upgraded: rerun)".to_string(),
        75 => "gave up waiting for atc at ATC_MAX_WAIT: the host was busy (atc's waiting line above says why; unset ATC_MAX_WAIT to wait until it frees)".to_string(),
        76 => cap.map_or_else(
            || "exceeded its memory cap (atc --ram-max)".to_string(),
            |c| format!("exceeded its memory cap of {c} (atc --ram-max)"),
        ),
        77 => "never fits this host's RAM budget".to_string(),
        78 if held => format!(
            "{refused}; xtask runs inside an `atc run`: xtask wraps its steps, nothing wraps xtask"
        ),
        78 => refused.to_string(),
        79 => "atc: the run was disturbed".to_string(),
        _ => return None,
    })
}

/// Whether this process runs inside an `atc run` (`ATC_HELD` set and not
/// empty).
#[must_use]
pub fn held() -> bool {
    std::env::var_os("ATC_HELD").is_some_and(|v| !v.is_empty())
}
/// A failed cargo gate's message: atc's own code when reserved, else the
/// command's exit or signal. `shown` is the command as the gate names it.
#[must_use]
pub fn gate_failure(reserve: &Reserve, shown: &str, code: Option<i32>, held: bool) -> String {
    let atc = match reserve {
        Reserve::Atc { .. } => code.and_then(|c| exit_message(c, None, held)),
        Reserve::None => None,
    };
    let held_by_atc = matches!(reserve, Reserve::Atc { .. });
    match (atc, code) {
        (Some(m), _) => format!("`{shown}`: {m}"),
        // atc returns 128 + N when signal N killed the command.
        (None, Some(c @ 129..=192)) if held_by_atc => {
            format!("`{shown}` was killed by signal {}", c - 128)
        }
        (None, Some(c)) => format!("`{shown}` failed (exit {c})"),
        (None, None) => format!("`{shown}` was killed by a signal"),
    }
}
