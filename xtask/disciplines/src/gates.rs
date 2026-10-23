// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Gate bodies: spawn tools and read exit codes. No logic lives here; this
//! file is the only legitimate coverage exemption.
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use crate::{
    atc, changelog, duplication, fmt_gate, layers, listed, proofs, ratchet, shell, sleeps, stubs,
    timing, tools, trusted, vir_trust,
};

/// Runs `program` in `root`. Public for project runners that extend this
/// one (`Runner::extending`).
///
/// # Errors
/// The program failing, or not starting.
pub fn run(root: &Path, program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{program} {}` failed ({status})", args.join(" ")))
    }
}

/// `run` for a heavy cargo gate: under `atc run --name <repo>/gate:<gate>`
/// when atc answers. Public for project runners that extend this one
/// (`Runner::extending`).
///
/// # Errors
/// The command failing, or atc refusing it.
pub fn heavy(root: &Path, gate: &str, program: &str, args: &[&str]) -> Result<(), String> {
    heavy_run(root, gate, program, args, &[], false)
        .map(|_| ())
        .map_err(|(failure, _)| failure)
}

/// [`heavy`] with stdout captured (stderr still shown): what the command
/// printed, whether it succeeded or not, and its failure as [`heavy`]
/// reports it.
///
/// # Errors
/// When the command cannot start, or atc cannot be asked.
pub fn heavy_output(
    root: &Path,
    gate: &str,
    program: &str,
    args: &[&str],
    env: &[(String, String)],
) -> Result<(String, Option<String>), String> {
    match heavy_run(root, gate, program, args, env, true) {
        Ok(stdout) => Ok((stdout, None)),
        Err((failure, Some(stdout))) => Ok((stdout, Some(failure))),
        Err((failure, None)) => Err(failure),
    }
}

/// The command under atc; `Err` holds the failure and, when it ran and
/// `capture` was asked, its stdout.
fn heavy_run(
    root: &Path,
    gate: &str,
    program: &str,
    args: &[&str],
    env: &[(String, String)],
    capture: bool,
) -> Result<String, (String, Option<String>)> {
    let reserve = atc::reserve(root);
    let gpu = match reserve {
        atc::Reserve::Atc { .. } => proofs::repo_gpu(&cargo_metadata(root).map_err(|e| (e, None))?),
        atc::Reserve::None => false,
    };
    let mut command = vec![program.to_string()];
    command.extend(args.iter().map(|a| (*a).to_string()));
    let wrapped = atc::wrap(&reserve, gate, gpu, command);
    let mut cmd = Command::new(&wrapped[0]);
    cmd.args(&wrapped[1..]).current_dir(root);
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
    let events = match reserve {
        atc::Reserve::Atc { .. } => timing::Stream::new(atc::held()),
        atc::Reserve::None => None,
    };
    // Without a stream of ours, none of the caller's either.
    match events.as_ref().map(timing::Stream::env) {
        Some((name, path)) => cmd.env(name, path),
        None => cmd.env_remove(timing::EVENTS_ENV),
    };
    let started = |e: std::io::Error| (format!("cannot run {}: {e}", wrapped[0]), None);
    let (status, stdout) = if capture {
        let out = cmd
            .stderr(std::process::Stdio::inherit())
            .output()
            .map_err(started)?;
        (
            out.status,
            Some(String::from_utf8_lossy(&out.stdout).into_owned()),
        )
    } else {
        (cmd.status().map_err(started)?, None)
    };
    if let Some(e) = events {
        let _ = e.finish();
    }
    if status.success() {
        Ok(stdout.unwrap_or_default())
    } else {
        let shown = format!("{program} {}", args.join(" "));
        let failure = atc::gate_failure(&reserve, &shown, status.code(), atc::held());
        Err((failure, stdout))
    }
}

/// # Errors
/// Names every missing tool with its install line, and any proof
/// declaration error.
pub fn preflight(root: &Path) -> Result<(), String> {
    let mut errors = Vec::new();
    let gone = tools::missing(tools::REQUIRED, &tools::on_path);
    if !gone.is_empty() {
        errors.push(tools::report(&gone));
    }
    match declared_proofs(root) {
        Err(e) => errors.push(e),
        Ok(d) => {
            let need = proofs::required_tools(&d.proofs);
            let gone = tools::missing(&need, &tools::on_path);
            if !gone.is_empty() {
                errors.push(tools::report(&gone));
            }
        }
    }
    let manifest = root.join("Cargo.toml");
    let checked = cargo_metadata(root).and_then(|json| {
        let text =
            read(&manifest).map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
        crate::cache::not_inputs::check(&json, &text)
    });
    if let Err(e) = checked {
        errors.push(e);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// The proof declarations from `cargo metadata`.
///
/// # Errors
/// `cargo metadata` failing, or a declaration error.
pub fn declared_proofs(root: &Path) -> Result<proofs::Declared, String> {
    let mut declared = proofs::parse(&cargo_metadata(root)?)?;
    let manifest = root.join("Cargo.toml");
    let text = read(&manifest).map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    proofs::widen_for_patches(&mut declared, &text);
    // Empty counts as unset, as in the cache key.
    let set = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    let cargo_home = set("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| set("HOME").map(|h| std::path::PathBuf::from(h).join(".cargo")));
    // Each proof's own: a command runs in its package directory, so cargo
    // also reads the configs between it and the root.
    for p in &mut declared.proofs {
        let patched = proofs::cargo_config_paths(&root.join(p.workdir()), cargo_home.as_deref())
            .iter()
            // A missing or unreadable config holds no patch.
            .any(|config| read(config).is_ok_and(|text| proofs::patches(&text)));
        if patched {
            p.dirs = vec![String::new()];
            p.contract = None;
        }
    }
    Ok(declared)
}

/// # Errors
/// The failed harnesses (Kani), or the command's timeout, failure or kill.
pub fn proof(root: &Path, p: &proofs::Proof, budget: u64) -> Result<(), String> {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    proof_run(root, p, proofs::jobs(cores, budget, p.memory), false).0
}

/// One proof run with `jobs` Kani jobs, reserved through atc when it answers.
/// With `capture`, everything it prints (a command prover's output included)
/// comes back as the log. A missing prover fails it with the install line.
pub fn proof_run(
    root: &Path,
    p: &proofs::Proof,
    jobs: usize,
    capture: bool,
) -> (Result<(), String>, String) {
    let need = proofs::gate_tools(p);
    let gone = tools::missing(&need, &tools::on_path);
    if !gone.is_empty() {
        return (Err(tools::report(&gone)), String::new());
    }
    proof_run_as(root, p, jobs, capture, &atc::reserve(root))
}

/// `proof_run` with the reservation given: tests pass `Reserve::None`.
pub fn proof_run_as(
    root: &Path,
    p: &proofs::Proof,
    jobs: usize,
    capture: bool,
    reserve: &atc::Reserve,
) -> (Result<(), String>, String) {
    if p.kind == proofs::Kind::Verus
        && let Err(e) = trusted_scan(root, p)
    {
        return (Err(e), String::new());
    }
    logged(capture, |log| match reserve {
        atc::Reserve::Atc { repo } => proof_under_atc(root, p, jobs, repo, log),
        atc::Reserve::None => proof_with(root, p, jobs, log),
    })
}

/// # Errors
/// Every line of the package's Rust sources with `#[verifier::external]` // disciplines:allow-trusted (documents the construct)
/// (trusted on a trait impl; `--no-cheating` does not reject it), or with
/// what builds differently from how Verus verified it (`trusted::cfg_scan`),
/// and no marker; a build script; or an unreadable listing, file or
/// metadata.
fn trusted_scan(root: &Path, p: &proofs::Proof) -> Result<(), String> {
    let prefix = if p.dir.is_empty() {
        String::new()
    } else {
        format!("{}/", p.dir)
    };
    let files: Vec<String> = listed::files(root)?
        .into_iter()
        .filter(|f| f.starts_with(&prefix) && Path::new(f).extension().is_some_and(|e| e == "rs"))
        .collect();
    let read = |f: &str| std::fs::read_to_string(root.join(f)).map_err(|e| format!("{f}: {e}"));
    let (hits, cfgs) = trusted::package_hits(&files, &read)?;
    let mut errors = Vec::new();
    if !hits.is_empty() {
        errors.push(format!(
            "{}\nVerus takes these on trust. Prove them, or mark each line with `{} (<reason>)`.",
            hits.join("\n"),
            trusted::MARKER
        ));
    }
    if !cfgs.is_empty() {
        errors.push(format!(
            "{}\nThese build differently from how Verus verified them (a `cfg` beyond `test`, `include!`, `env!`, `option_env!`, `#[path]`). Remove them, or mark each line with `{} (<reason>)`.",
            cfgs.join("\n"),
            trusted::MARKER
        ));
    }
    if vir_trust::has_build_script(&cargo_metadata(root)?, &p.package)? {
        errors.push(format!(
            "package `{}` has a build script: its `cargo:rustc-cfg` can build the code differently from how Verus verified it; move it out of the proved crate",
            p.package
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Where a proof's report lines go: stderr as they come, or a log the
/// parallel batch prints whole.
pub struct ProofLog {
    capture: bool,
    log: String,
}

impl ProofLog {
    pub fn line(&mut self, line: &str) {
        if self.capture {
            self.log.push_str(line);
            self.log.push('\n');
        } else {
            eprintln!("{line}");
        }
    }
}

/// Runs `f` with a log; a panic in `f` becomes its failure, and what it
/// logged before is kept.
pub fn logged(
    capture: bool,
    f: impl FnOnce(&mut ProofLog) -> Result<(), String>,
) -> (Result<(), String>, String) {
    let mut log = ProofLog {
        capture,
        log: String::new(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&mut log)))
        .unwrap_or_else(|_| Err("the proof panicked".to_string()));
    (result, log.log)
}

/// Runs `cmd` with stdout and stderr on one pipe, so their lines keep the
/// order the prover wrote them in. `live` sees each line as it arrives.
fn merged_output(
    mut cmd: Command,
    live: &mut dyn FnMut(&str),
) -> std::io::Result<(String, Option<i32>)> {
    use std::io::BufRead;
    let (reader, writer) = std::io::pipe()?;
    cmd.stdout(writer.try_clone()?).stderr(writer);
    let mut child = cmd.spawn()?;
    // The parent's copies of the write end must close, or the read never
    // reaches end of file.
    drop(cmd);
    let mut reader = std::io::BufReader::new(reader);
    let mut text = String::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        let s = String::from_utf8_lossy(&buf);
        live(s.trim_end_matches('\n'));
        text.push_str(&s);
    }
    let status = child.wait()?;
    Ok((text, status.code()))
}

fn proof_with(
    root: &Path,
    p: &proofs::Proof,
    jobs: usize,
    say: &mut ProofLog,
) -> Result<(), String> {
    let cap_bytes = proofs::cgroup_cap(p, jobs);
    let alive = |pid: u32| Path::new("/proc").join(pid.to_string()).exists();
    let ns = std::fs::read_link("/proc/self/ns/pid")
        .ok()
        .and_then(|l| proofs::cgroup::pid_ns(&l.to_string_lossy()))
        .unwrap_or(0);
    let created = read(Path::new("/proc/self/cgroup"))
        .map_err(|_| "no /proc/self/cgroup".to_string())
        .and_then(|text| {
            proofs::cgroup::create(
                Path::new("/sys/fs/cgroup"),
                &text,
                &proofs::cgroup::run_name(&p.name, ns, std::process::id()),
                cap_bytes,
                ns,
                &alive,
            )
        });
    let cap = match &created {
        Ok(path) => proofs::Cap::Cgroup(path.clone()),
        Err(reason) => {
            say.line(&format!("memory cap: prlimit ({reason})"));
            proofs::Cap::Prlimit
        }
    };
    // Dropped on any exit, an unwind included: the run's cgroup never outlives it.
    let cgroup = created
        .ok()
        .map(|path| proofs::cgroup::Guard::new(path, cap_bytes));
    let argv = proofs::argv(p, jobs, &cap);
    let out = spawn_driver(root, p, &argv, None, say);
    // Read even when the spawn failed: the guard removes the cgroup either way.
    let usage = finish_cgroup(cgroup, say);
    let (text, code) = out?;
    match p.kind {
        proofs::Kind::Kani => proofs::kani_report(p, &text, code, usage.as_ref()).map(|()| {
            if let Some(warning) = proofs::harness_budget_report(p, &text) {
                say.line(&warning);
            }
        }),
        proofs::Kind::Verus => verus_trusted(root, &text)
            .and_then(|judged| proofs::verus_report(p, judged, code, usage.as_ref()))
            .and_then(|()| vir_trust_check(root, p, say)),
        proofs::Kind::Command(_) => proofs::command_report(p, code, usage.as_ref()),
    }
}

/// `spawn_raw`, with a Kani run's exit code read against its deadline
/// (`proofs::exit_after`); Verus and command runs have a CPU limit instead,
/// which reports itself (exit 152).
fn spawn_driver(
    root: &Path,
    p: &proofs::Proof,
    argv: &[String],
    events: Option<timing::Stream>,
    say: &mut ProofLog,
) -> Result<(String, Option<i32>), String> {
    let start = std::time::Instant::now();
    let spawned = spawn_raw(root, p, argv, events.as_ref(), say);
    // What atc held the run (waiting for admission) is not the run's time.
    let held = events
        .and_then(timing::Stream::finish)
        .map_or(std::time::Duration::ZERO, |s| s.waited + s.paused);
    let (text, code) = spawned?;
    if p.kind != proofs::Kind::Kani {
        return Ok((text, code));
    }
    let ran = start.elapsed().saturating_sub(held);
    Ok((text, proofs::exit_after(code, ran, proofs::deadline_s(p))))
}

/// Spawns `argv` in the package directory: the Kani output (kept out of the
/// log, its slowest harnesses said) or a command's (logged when captured),
/// and the exit code. `events`: the `atc run`'s job-events file.
fn spawn_raw(
    root: &Path,
    p: &proofs::Proof,
    argv: &[String],
    events: Option<&timing::Stream>,
    say: &mut ProofLog,
) -> Result<(String, Option<i32>), String> {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(root.join(p.workdir()));
    match events.map(timing::Stream::env) {
        Some((name, path)) => cmd.env(name, path),
        None => cmd.env_remove(timing::EVENTS_ENV),
    };
    for name in proofs::DROPPED_ENV {
        cmd.env_remove(name);
    }
    let cannot = |e: std::io::Error| format!("cannot run {}: {e}", argv[0]);
    let gate = p.gate_name();
    let mut live = |line: &str| {
        if proofs::live_line(line) {
            eprintln!("{gate}: {line}");
        }
    };
    match p.kind {
        proofs::Kind::Kani => {
            let (text, code) = merged_output(cmd, &mut live).map_err(cannot)?;
            let slow = proofs::slowest(&proofs::kani_times(&text), 3);
            if !slow.is_empty() {
                say.line(&slow);
            }
            Ok((text, code))
        }
        proofs::Kind::Verus => {
            let (text, code) = merged_output(cmd, &mut live).map_err(cannot)?;
            if say.capture {
                say.log.push_str(&text);
            } else if let Some((verified, errors)) = proofs::verus_results(&text) {
                say.line(&format!(
                    "verification results: {verified} verified, {errors} errors"
                ));
            }
            Ok((text, code))
        }
        proofs::Kind::Command(_) if say.capture => {
            let (text, code) = merged_output(cmd, &mut live).map_err(cannot)?;
            say.log.push_str(&text);
            Ok((String::new(), code))
        }
        proofs::Kind::Command(_) => Ok((String::new(), cmd.status().map_err(cannot)?.code())),
    }
}

fn proof_under_atc(
    root: &Path,
    p: &proofs::Proof,
    jobs: usize,
    repo: &str,
    say: &mut ProofLog,
) -> Result<(), String> {
    let cap = proofs::Cap::Atc {
        repo: repo.to_string(),
        never_pause: crate::atc::never_pause(
            std::env::var_os(crate::atc::NEVER_PAUSE_ENV).as_deref(),
        ),
    };
    let argv = proofs::argv(p, jobs, &cap);
    let events = timing::Stream::new(atc::held());
    let (text, code) = spawn_driver(root, p, &argv, events, say)?;
    // atc's own lines (its peak, an OOM) went to stderr: in Kani's output,
    // which stays out of the log, so say them.
    for line in text
        .lines()
        .filter(|l| l.starts_with("atc: ") && !proofs::live_line(l))
    {
        say.line(line);
    }
    let cap = proofs::cgroup_cap(p, jobs);
    match p.kind {
        proofs::Kind::Verus => verus_trusted(root, &text)
            .and_then(|judged| proofs::atc_report(p, judged, code, cap, atc::held()))
            .and_then(|()| vir_trust_check(root, p, say)),
        proofs::Kind::Kani => proofs::atc_report(p, &text, code, cap, atc::held()).map(|()| {
            if let Some(warning) = proofs::harness_budget_report(p, &text) {
                say.line(&warning);
            }
        }),
        proofs::Kind::Command(_) => proofs::atc_report(p, &text, code, cap, atc::held()),
    }
}

/// # Errors
/// Each external entry of the package's own crate in the Verus logs that
/// is neither explained nor marked (`vir_trust::judge`), a missing or
/// unreadable log, or `cargo metadata` failing. External free functions and
/// inherent methods are printed.
fn vir_trust_check(root: &Path, p: &proofs::Proof, say: &mut ProofLog) -> Result<(), String> {
    let dir = Path::new(&proofs::verus_build_dir(p)).join("log");
    let log = |name: &str| {
        std::fs::read_to_string(dir.join(name)).map_err(|e| {
            format!(
                "{}: {e} (the Verus driver writes it with --log-dir)",
                dir.join(name).display()
            )
        })
    };
    let (vir, names) = (log("crate.vir")?, log("crate.impl_names")?);
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let metadata = String::from_utf8_lossy(&out.stdout);
    let proved: Vec<String> = declared_proofs(root)?
        .proofs
        .into_iter()
        .filter(|e| e.kind == proofs::Kind::Verus)
        .map(|e| e.package)
        .collect();
    let foreign = vir_trust::foreign_deps(&metadata, &p.package, &proved)?;
    let proc_macros = vir_trust::proc_macros(&metadata, &p.package)?;
    let krate = vir_trust::lib_name(&metadata, &p.package)?;
    let source = |file: &str, n: usize| {
        std::fs::read_to_string(root.join(file))
            .ok()
            .and_then(|t| t.lines().nth(n.checked_sub(1)?).map(str::to_string))
    };
    let judged = vir_trust::judge(&krate, &vir, &names, &proc_macros, &source)?;
    for path in judged.listed {
        say.line(&format!(
            "verus: external, not callable from verified code: {path}"
        ));
    }
    let mut failures = judged.failures;
    if !foreign.is_empty() {
        let names: Vec<String> = foreign.iter().map(|d| format!("`{d}`")).collect();
        failures.push(format!(
            "`{}` depends on {}: neither Verus's crates nor a Verus-proved workspace crate, so its macros and re-exports reach the proved code unscanned; prove it in its own entry, or exempt it with a reason under `[package.metadata.disciplines] trusted_deps`",
            p.package,
            names.join(", ")
        ));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

/// # Errors
/// As `proofs::verus_trust`, reading the named lines from `root`.
fn verus_trusted<'a>(root: &Path, text: &'a str) -> Result<&'a str, String> {
    proofs::verus_trust(text, |path, number| {
        std::fs::read_to_string(root.join(path))
            .ok()
            .and_then(|f| f.lines().nth(number.saturating_sub(1)).map(str::to_string))
    })
}

/// Reads and removes the run's cgroup, reporting its peak and any cleanup
/// warnings; `None` under prlimit.
fn finish_cgroup(
    guard: Option<proofs::cgroup::Guard>,
    say: &mut ProofLog,
) -> Option<proofs::cgroup::Usage> {
    let (usage, warnings) = guard?.finish();
    for w in warnings {
        say.line(&format!("warning: {w}"));
    }
    let line = proofs::peak_line(&usage);
    if !line.is_empty() {
        say.line(&line);
    }
    Some(usage)
}

/// # Errors
/// When the tree is not formatter-clean: rustfmt, then verusfmt over the
/// Rust sources that invoke `verus!` (rustfmt leaves macro bodies alone). A
/// file verusfmt cannot parse fails too (user, 2026-10-13: rewrite the
/// construct; verusfmt 0.7.4 cannot parse a shift-assign onto a field,
/// `s.low <<= 8`). An indented `verus!` fails (`fmt_gate::indented_verus`).
pub fn fmt(root: &Path) -> Result<(), String> {
    run(root, "cargo", &["fmt", "--all", "--check"])?;
    let (mut verus, mut indented) = (Vec::new(), Vec::new());
    for f in listed::files(root)? {
        if Path::new(&f).extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let bytes = std::fs::read(root.join(&f)).map_err(|e| format!("{f}: {e}"))?;
        let text = String::from_utf8_lossy(&bytes);
        if fmt_gate::invokes_verus(&text) {
            indented.extend(
                fmt_gate::indented_verus(&text)
                    .into_iter()
                    .map(|n| format!("{f}:{n}")),
            );
            verus.push(f);
        }
    }
    if !indented.is_empty() {
        return Err(format!(
            "{}\n`verus!` must start at column 0: verusfmt lays the block out from there and rustfmt re-indents it, so an indented block passes neither",
            indented.join("\n")
        ));
    }
    if verus.is_empty() {
        return Ok(());
    }
    if !tools::on_path("verusfmt") {
        return Err(format!(
            "{}\nfiles: {}",
            fmt_gate::VERUSFMT_HINT,
            verus.join(" ")
        ));
    }
    let mut args = vec!["--check", "--verus-only"];
    args.extend(verus.iter().map(String::as_str));
    run(root, "verusfmt", &args)
}

/// # Errors
/// A warning or error no ratchet budgets, a ratchet count that moved, an
/// allow without a justification, a package with no lint policy, or clippy
/// failing (`ratchet`; the skill's `gates.md`, lint).
pub fn lint(root: &Path) -> Result<(), String> {
    lint_at(root, "lint", None)
}

/// `cargo xtask ratchet`: every clippy lint a lint table allows, with its
/// count from clippy runs warning on each table's allowed lints, as ready
/// ratchet lines; the policy's own errors (an unjustified allow, a package
/// with no policy) follow as comments.
///
/// # Errors
/// Unreadable metadata or manifests, or clippy failing.
pub fn ratchet_measure(root: &Path) -> Result<String, String> {
    let metadata = cargo_metadata(root)?;
    let policy = ratchet::policy(&metadata, &read)?;
    let groups = ratchet::groups(&policy, true);
    let (json, failures) = clippy_runs(root, "ratchet", None, &policy.build_root, &groups)?;
    if let Some(failure) = failures.into_iter().next() {
        return Err(failure);
    }
    let mut text = ratchet::measure(&policy, &json);
    for e in &policy.errors {
        let _ = writeln!(text, "# {e}");
    }
    Ok(text)
}

/// [`lint`] for the workspace whose manifest is `manifest` (relative to
/// `root`), or `root`'s own. Clippy runs with JSON output once per group of
/// packages ratcheting the same lints ([`ratchet::groups`]), with `-W
/// warnings` (so an allowed `warnings` group hides nothing) and `-W` for
/// that group's ratcheted lints, never `-D warnings`: a crate's findings
/// must not stop cargo before the crates depending on it.
///
/// # Errors
/// As [`lint`].
pub fn lint_at(root: &Path, gate: &str, manifest: Option<&str>) -> Result<(), String> {
    let mut path = Vec::new();
    if let Some(m) = manifest {
        path.extend(["--manifest-path", m]);
    }
    let metadata = cargo_metadata_with(root, &path)?;
    let policy = ratchet::policy(&metadata, &read)?;
    let groups = ratchet::groups(&policy, false);
    let (json, failed) = clippy_runs(root, gate, manifest, &policy.build_root, &groups)?;
    let verdict = ratchet::judge(&policy, &json);
    let mut errors = policy.errors.clone();
    errors.extend(verdict.findings);
    if failed.is_empty() {
        errors.extend(verdict.counts);
    }
    errors.extend(failed);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// One `cargo clippy --message-format=json` per run (the whole workspace
/// when there is one run, else `-p` per package, each run in its own build
/// directory, [`ratchet::run_dir`]): the JSON of all, each run's kept to
/// its own packages ([`ratchet::own`]), and each run's failure.
fn clippy_runs(
    root: &Path,
    gate: &str,
    manifest: Option<&str>,
    build_root: &str,
    runs: &[ratchet::Run],
) -> Result<(String, Vec<String>), String> {
    let mut json = String::new();
    let mut failed = Vec::new();
    for run in runs {
        let mut args: Vec<String> = vec!["clippy".to_string()];
        if let Some(m) = manifest {
            args.extend(["--manifest-path".to_string(), m.to_string()]);
        }
        if runs.len() == 1 {
            args.push("--workspace".to_string());
        } else {
            args.extend(
                run.packages
                    .iter()
                    .flat_map(|p| ["-p".to_string(), p.clone()]),
            );
        }
        args.extend(
            [
                "--all-targets",
                "--locked",
                "--message-format=json",
                "--",
                "-W",
                "warnings",
            ]
            .map(String::from),
        );
        args.extend(
            run.warn
                .iter()
                .flat_map(|l| ["-W".to_string(), format!("clippy::{l}")]),
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        // Clippy's arguments are in cargo's fingerprints: runs sharing a
        // directory would re-check each other's members on every gate run.
        let env: Vec<(String, String)> = if runs.len() == 1 {
            Vec::new()
        } else {
            let dir = ratchet::run_dir(build_root, run);
            ["CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR"]
                .map(|k| (k.to_string(), dir.clone()))
                .to_vec()
        };
        let (out, failure) = heavy_output(root, gate, "cargo", &args, &env)?;
        json.push_str(&ratchet::own(run, &out));
        failed.extend(failure);
    }
    Ok((json, failed))
}

/// # Errors
/// On a duplicate group the baseline does not cover.
pub fn duplication(root: &Path) -> Result<(), String> {
    duplication::gate(root)
}

/// # Errors
/// When any test fails.
pub fn test(root: &Path) -> Result<(), String> {
    heavy(root, "test", "cargo", &["test", "--workspace", "--locked"])
}

fn cargo_metadata(root: &Path) -> Result<String, String> {
    cargo_metadata_with(root, &[])
}

/// `cargo metadata --no-deps` in `root`, with `extra` arguments (a
/// `--manifest-path`).
fn cargo_metadata_with(root: &Path, extra: &[&str]) -> Result<String, String> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps", "--locked"])
        .args(extra)
        .current_dir(root)
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`cargo metadata` failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("cargo metadata: output is not UTF-8: {e}"))
}

fn read(path: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

/// # Errors
/// Lists every layer violation: undeclared or unknown layers, dependencies
/// outside `allow`, forbidden edges, missing lint opt-ins, missing `no_std`,
/// haircomb rules, proof coverage and primitive source rules.
pub fn layers(root: &Path) -> Result<(), String> {
    let json = cargo_metadata(root)?;
    let packages = layers::parse_metadata(&json, &read)?;
    let manifest = root.join("Cargo.toml");
    let root_manifest =
        read(&manifest).map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    let comb = layers::comb(&json)?;
    let declared = proofs::parse(&json)?;
    let proved: Vec<(&str, &proofs::Kind)> = declared
        .proofs
        .iter()
        .map(|p| (p.package.as_str(), &p.kind))
        .collect();
    let mut violations = layers::check(&packages, &root_manifest);
    // `root` may be `<ws>/xtask/..`; cargo reports canonical paths.
    let base = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    violations.extend(layers::check_comb(&packages, &comb));
    violations.extend(layers::coverage(&packages, &comb, &proved));
    for p in &packages {
        if let (Some(lib), Some("primitive")) = (p.lib_path.as_deref(), p.layer.as_deref()) {
            violations.extend(primitive_violations(root, &base, &p.name, lib)?);
        }
    }
    layers::report(&violations)
}

/// A primitive crate's source rules, over every file its module tree
/// reaches: sources that can't be read or keyed, then each file's findings.
fn primitive_violations(
    root: &Path,
    base: &Path,
    package: &str,
    lib: &Path,
) -> Result<Vec<layers::Violation>, String> {
    let shown = |file: &Path| {
        file.strip_prefix(base)
            .unwrap_or(file)
            .display()
            .to_string()
    };
    let mut out = Vec::new();
    let mut push = |message: String| {
        out.push(layers::Violation {
            package: package.to_string(),
            message,
        });
    };
    let sources = layers::primitive::crate_sources(lib)?;
    for problem in &sources.problems {
        push(format!(
            "{}:{}: {}",
            shown(&problem.file),
            problem.line,
            problem.message
        ));
    }
    // The gate's cache keys only what git sees, so an ignored source, or
    // one outside the repository, could change unseen.
    let (ignored, outside) = layers::primitive::ignored(root, &sources.files)?;
    for file in ignored {
        push(format!(
            "{}: ignored by git; a primitive's sources must not be ignored, or the gate's cache cannot see them change",
            shown(&file)
        ));
    }
    for file in outside {
        push(format!(
            "{}: outside the repository; a primitive's sources must be in it, or the gate's cache cannot see them change",
            shown(&file)
        ));
    }
    for file in &sources.files {
        let source = read(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        for finding in layers::primitive::findings(&shown(file), &source)? {
            push(finding);
        }
    }
    Ok(out)
}

/// # Errors
/// When a kernel or core crate does not build for the `no_std` target.
pub fn no_std(root: &Path) -> Result<(), String> {
    let json = cargo_metadata(root)?;
    let packages = layers::parse_metadata(&json, &read)?;
    let target = layers::no_std_target(&json)?;
    for name in layers::no_std_crates(&packages)? {
        heavy(
            root,
            &format!("no-std:{name}"),
            "cargo",
            &[
                "build", "-p", name, "--lib", "--target", &target, "--locked",
            ],
        )?;
    }
    Ok(())
}

/// # Errors
/// Every unmarked finding, every stale vocabulary term, an unreadable or
/// malformed vocabulary, or when no source file is found.
pub fn stub_scan(root: &Path) -> Result<(), String> {
    let terms = match std::fs::read_to_string(root.join(stubs::VOCABULARY)) {
        Ok(text) => stubs::parse_vocabulary(&text)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", stubs::VOCABULARY)),
    };
    let mut used = vec![false; terms.len()];
    let files = listed::files(root)?;
    let mut scanned = 0;
    let mut hits = Vec::new();
    for f in &files {
        let ext = Path::new(f).extension().and_then(|e| e.to_str());
        let source = ext.is_some_and(|e| stubs::EXTENSIONS.contains(&e))
            || (ext.is_none() && shell::is_shell_script(f, &listed::first_line(root, f)));
        if !source {
            continue;
        }
        let text = std::fs::read_to_string(root.join(f)).map_err(|e| format!("{f}: {e}"))?;
        scanned += 1;
        hits.extend(
            stubs::scan_with(&text, &terms, &mut used)
                .into_iter()
                .map(|h| format!("{f}:{}: {}", h.line, h.text)),
        );
    }
    if scanned == 0 {
        return Err("no source files found: the gate would pass vacuously".to_string());
    }
    hits.extend(
        terms
            .iter()
            .zip(&used)
            .filter(|(_, used)| !**used)
            .map(|(t, _)| format!("{}: stale term `{t}`: it exempts no hit", stubs::VOCABULARY)),
    );
    if hits.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}\nWrite the real thing, or record a DEFERRED.md entry. A genuine false positive \
             carries `{} (<reason>)` on its line.",
            hits.join("\n"),
            stubs::MARKER
        ))
    }
}

/// # Errors
/// Every unmarked sleep and every invalid or stale marker, when
/// `DEFERRED.md` cannot be read, or when no Rust source is found.
pub fn sleep_scan(root: &Path) -> Result<(), String> {
    let ledger = std::fs::read_to_string(root.join("DEFERRED.md"))
        .map_err(|e| format!("DEFERRED.md: {e}"))?;
    let ledger = sleeps::ledger(&ledger);
    let mut scanned = 0;
    let mut hits = Vec::new();
    for f in listed::files(root)? {
        let ext = Path::new(&f).extension().and_then(|e| e.to_str());
        if !ext.is_some_and(|e| sleeps::EXTENSIONS.contains(&e)) {
            continue;
        }
        let text = std::fs::read_to_string(root.join(&f)).map_err(|e| format!("{f}: {e}"))?;
        scanned += 1;
        hits.extend(
            sleeps::scan(&text, &ledger)
                .into_iter()
                .map(|h| format!("{f}:{}: {} ({})", h.line, h.text, h.why)),
        );
    }
    if scanned == 0 {
        return Err("no Rust sources found: the gate would pass vacuously".to_string());
    }
    if hits.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}\nWait on a handshake or an event. A sleep kept on purpose carries \
             `{} (D<n>)` on its line, citing an ACCEPTED DEFERRED.md entry.",
            hits.join("\n"),
            sleeps::MARKER
        ))
    }
}

/// # Errors
/// When the comparison `changelog::check` makes fails, or git cannot say
/// what to compare.
pub fn changelog(root: &Path) -> Result<(), String> {
    let hook_main = std::env::var_os(crate::CONTEXT_ENV).is_some_and(|v| v == "main");
    let main = crate::main_branch_name(std::env::var_os(crate::MAIN_BRANCH_ENV));
    changelog_in(root, hook_main, &main)
}

/// [`changelog`], with the hook's context and the main branch's name passed
/// in rather than read from the environment.
///
/// # Errors
/// As [`changelog`].
pub fn changelog_in(root: &Path, hook_main: bool, main: &str) -> Result<(), String> {
    let branch = git_out(root, &["symbolic-ref", "--short", "-q", "HEAD"]).ok();
    let disk = || {
        std::fs::read_to_string(root.join("CHANGELOG.md")).map_err(|e| format!("CHANGELOG.md: {e}"))
    };
    let (old, new) = match changelog::context(hook_main, branch.as_deref(), main)? {
        changelog::Context::Merging => (file_at(root, "HEAD")?, disk()?),
        // Before the first commit, and at a root commit (a generated
        // project's first), the whole file is new; after that, main moves
        // only by merges.
        changelog::Context::MainTip
            if git_out(root, &["rev-parse", "--verify", "-q", "HEAD"]).is_err() =>
        {
            (String::new(), disk()?)
        }
        changelog::Context::MainTip
            if git_out(root, &["rev-parse", "--verify", "-q", "HEAD^1"]).is_err() =>
        {
            (String::new(), file_at(root, "HEAD")?)
        }
        changelog::Context::MainTip => {
            git_out(root, &["rev-parse", "--verify", "-q", "HEAD^2"])
                .map_err(|_| format!("HEAD on {main} is not a merge: main moves only by merges"))?;
            (file_at(root, "HEAD^1")?, file_at(root, "HEAD")?)
        }
        // The base is main, or a remote's main in a clone that never
        // checked it out; with neither, nothing is on main yet and the whole
        // file is new.
        changelog::Context::Branch => match main_ref(root, main) {
            Some(main_ref) => {
                let base = git_out(root, &["merge-base", &main_ref, "HEAD"])?;
                (file_at(root, &base)?, disk()?)
            }
            None => (String::new(), disk()?),
        },
    };
    changelog::check(&old, &new)
}

/// `refs/heads/<main>`; else, in a clone that never checked it out, its
/// upstream, `refs/remotes/origin/<main>`, or another remote's, in that
/// order (spec T7: a stale remote-tracking ref makes the base older).
fn main_ref(root: &Path, main: &str) -> Option<String> {
    let exists = |r: &str| git_out(root, &["rev-parse", "--verify", "-q", r]).is_ok();
    let local = format!("refs/heads/{main}");
    if exists(&local) {
        return Some(local);
    }
    let upstream = git_out(
        root,
        &[
            "for-each-ref",
            "--format=%(upstream)",
            &format!("refs/heads/{main}"),
        ],
    )
    .ok()
    .filter(|u| !u.is_empty());
    let origin = format!("refs/remotes/origin/{main}");
    let any = git_out(
        root,
        &[
            "for-each-ref",
            "--format=%(refname)",
            &format!("refs/remotes/*/{main}"),
        ],
    )
    .ok()
    .and_then(|r| r.lines().next().map(str::to_string));
    upstream
        .into_iter()
        .chain(exists(&origin).then_some(origin))
        .chain(any)
        .next()
}

/// `CHANGELOG.md` at `rev`; empty where it did not exist yet.
fn file_at(root: &Path, rev: &str) -> Result<String, String> {
    let spec = format!("{rev}:CHANGELOG.md");
    if git_out(root, &["cat-file", "-e", &spec]).is_err() {
        return Ok(String::new());
    }
    git_out(root, &["show", &spec])
}

fn git_out(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = crate::git::command()
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}
