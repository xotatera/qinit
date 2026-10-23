// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use xtask::cache::key::{Inputs, KeySpec, Probe, key, manifest};

/// A scratch directory removed when the test ends.
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("xtask-key-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn git(dir: &Path, args: &[&str]) {
    let ok = xtask::git::command()
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

fn write_exe(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// repo/ (a git repo with src/lib.rs, README.md, .gitignore ignoring `out/`,
/// committed), runner/ (one file), bin/ (an executable `cargo`).
fn setup(s: &Scratch) -> (PathBuf, Probe) {
    let repo = s.0.join("repo");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(repo.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    fs::write(repo.join("README.md"), "readme\n").unwrap();
    fs::write(repo.join(".gitignore"), "out/\n").unwrap();
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "init"]);
    let runner = s.0.join("runner");
    fs::create_dir_all(&runner).unwrap();
    fs::write(runner.join("gates.rs"), "// gate code\n").unwrap();
    let bin = s.0.join("bin");
    fs::create_dir_all(&bin).unwrap();
    write_exe(&bin.join("cargo"), "#!/bin/sh\n");
    let probe = Probe {
        runner_dirs: vec![runner],
        path: Some(OsString::from(bin.as_os_str())),
        sysroot: None,
        vars: HashMap::new(),
        home: Some(s.0.join("home")),
    };
    (repo, probe)
}

const TREE: KeySpec = KeySpec {
    gate: "lint",
    inputs: Inputs::Tree,
    env: &["RUSTFLAGS"],
    tools: &["cargo"],
    extra_paths: &[],
    ignored_inputs: &[],
    decl: "",
};
const RS: KeySpec = KeySpec {
    gate: "fmt",
    inputs: Inputs::Globs(&["**/*.rs"]),
    env: &[],
    tools: &["cargo"],
    extra_paths: &[],
    ignored_inputs: &[],
    decl: "",
};

#[test]
fn same_tree_same_key() {
    let s = scratch("same");
    let (repo, probe) = setup(&s);
    assert_eq!(key(&repo, &TREE, &probe), key(&repo, &TREE, &probe));
}

#[test]
fn tracked_unstaged_and_untracked_changes_change_a_tree_key() {
    let s = scratch("tree");
    let (repo, probe) = setup(&s);
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("src/lib.rs"), "pub fn b() {}\n").unwrap();
    let k1 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(k0, k1, "unstaged edit");
    fs::write(repo.join("new.txt"), "x").unwrap();
    let k2 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(k1, k2, "new untracked file");
    fs::create_dir_all(repo.join("out")).unwrap();
    fs::write(repo.join("out/build.log"), "x").unwrap();
    assert_eq!(k2, key(&repo, &TREE, &probe).unwrap(), "ignored file");
}

#[test]
fn deleting_a_tracked_input_changes_the_key() {
    let s = scratch("delete");
    let (repo, probe) = setup(&s);
    let k0 = key(&repo, &RS, &probe).unwrap();
    fs::remove_file(repo.join("src/lib.rs")).unwrap();
    assert_ne!(k0, key(&repo, &RS, &probe).unwrap());
}

#[test]
fn a_narrowed_key_ignores_files_outside_its_globs() {
    let s = scratch("narrow");
    let (repo, probe) = setup(&s);
    let (rs0, tree0) = (
        key(&repo, &RS, &probe).unwrap(),
        key(&repo, &TREE, &probe).unwrap(),
    );
    fs::write(repo.join("README.md"), "changed\n").unwrap();
    assert_eq!(rs0, key(&repo, &RS, &probe).unwrap());
    assert_ne!(tree0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn runner_lock_and_toolchain_changes_change_a_narrowed_key() {
    let s = scratch("extras");
    let (repo, probe) = setup(&s);
    let k0 = key(&repo, &RS, &probe).unwrap();
    fs::write(probe.runner_dirs[0].join("gates.rs"), "// changed\n").unwrap();
    let k1 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k0, k1, "runner source");
    fs::write(repo.join("Cargo.lock"), "lock\n").unwrap();
    let k2 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k1, k2, "Cargo.lock");
    fs::write(repo.join("rust-toolchain.toml"), "[toolchain]\n").unwrap();
    assert_ne!(k2, key(&repo, &RS, &probe).unwrap(), "toolchain file");
}

#[test]
fn tool_binary_changes_change_the_key() {
    let s = scratch("tool");
    let (repo, mut probe) = setup(&s);
    let k0 = key(&repo, &RS, &probe).unwrap();
    let cargo = s.0.join("bin/cargo");
    write_exe(&cargo, "#!/bin/sh\n# a different build\n");
    let k1 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k0, k1, "PATH binary size");
    let sysroot = s.0.join("sysroot");
    fs::create_dir_all(sysroot.join("bin")).unwrap();
    write_exe(&sysroot.join("bin/cargo"), "real cargo v1");
    probe.sysroot = Some(sysroot.clone());
    let k2 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k1, k2, "sysroot appears");
    write_exe(&sysroot.join("bin/cargo"), "real cargo v2, longer");
    assert_ne!(
        k2,
        key(&repo, &RS, &probe).unwrap(),
        "rustup update behind an unchanged proxy"
    );
}

#[test]
fn only_declared_env_vars_count() {
    let s = scratch("env");
    let (repo, mut probe) = setup(&s);
    let k0 = key(&repo, &TREE, &probe).unwrap();
    probe.vars.insert("UNRELATED".into(), "1".into());
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap());
    probe
        .vars
        .insert("RUSTFLAGS".into(), "-C opt-level=3".into());
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

/// DEFERRED D13: the variables rustup's proxy sets do not tell a run under
/// `cargo xtask` from the same binary started from a shell.
#[test]
fn rustup_proxy_variables_key_like_a_shell() {
    let s = scratch("proxy");
    let (repo, mut probe) = setup(&s);
    let shell = key(&repo, &TREE, &probe).unwrap();
    let home = s.0.join("home");
    for (k, v) in [
        (
            "RUSTUP_TOOLCHAIN",
            OsString::from("1.99.0-x86_64-unknown-linux-gnu"),
        ),
        ("RUSTUP_TOOLCHAIN_SOURCE", OsString::from("override")),
        ("CARGO_HOME", home.join(".cargo").into_os_string()),
        ("RUSTUP_HOME", home.join(".rustup").into_os_string()),
    ] {
        probe.vars.insert(k.into(), v);
    }
    assert_eq!(shell, key(&repo, &TREE, &probe).unwrap());
    // A home moved elsewhere still re-keys: cargo reads another config and
    // registry there.
    probe
        .vars
        .insert("CARGO_HOME".into(), s.0.join("elsewhere").into());
    assert_ne!(shell, key(&repo, &TREE, &probe).unwrap());
    probe
        .vars
        .insert("CARGO_HOME".into(), home.join(".cargo").into());
    probe
        .vars
        .insert("RUSTUP_HOME".into(), s.0.join("elsewhere").into());
    assert_ne!(shell, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn gates_with_identical_inputs_get_different_keys() {
    let s = scratch("name");
    let (repo, probe) = setup(&s);
    let other = KeySpec {
        gate: "duplication",
        ..RS
    };
    assert_ne!(key(&repo, &RS, &probe), key(&repo, &other, &probe));
}

#[test]
fn thousands_of_files_do_not_deadlock() {
    let s = scratch("many");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(repo.join("gen")).unwrap();
    for i in 0..5000 {
        fs::write(repo.join(format!("gen/f{i}.rs")), format!("// {i}\n")).unwrap();
    }
    assert!(key(&repo, &RS, &probe).is_ok());
}

#[test]
fn odd_paths() {
    let s = scratch("paths");
    let (repo, probe) = setup(&s);
    fs::write(repo.join("src/with space ü.rs"), "x").unwrap();
    assert!(key(&repo, &RS, &probe).is_ok());
    fs::write(repo.join("src/new\nline.rs"), "x").unwrap();
    assert!(key(&repo, &RS, &probe).unwrap_err().contains("newline"));
}

#[test]
fn outside_a_git_repository_there_is_no_key() {
    let s = scratch("nogit");
    let (_, probe) = setup(&s);
    let plain = s.0.join("plain");
    fs::create_dir_all(&plain).unwrap();
    assert!(key(&plain, &RS, &probe).is_err());
}

#[test]
fn entries_that_are_not_regular_files_make_the_key_an_error() {
    let s = scratch("irregular");
    let (repo, probe) = setup(&s);
    std::os::unix::fs::symlink("src", repo.join("linkdir")).unwrap();
    git(&repo, &["add", "-A"]);
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
    assert!(key(&repo, &RS, &probe).is_ok(), "narrowed key unaffected");
}

#[test]
fn an_untracked_nested_repository_makes_a_tree_key_an_error() {
    let s = scratch("nested");
    let (repo, probe) = setup(&s);
    let nested = repo.join("nested");
    fs::create_dir_all(&nested).unwrap();
    git(&nested, &["init", "-q", "-b", "main"]);
    fs::write(nested.join("f.txt"), "x").unwrap();
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
}

#[test]
fn the_executable_bit_changes_the_key() {
    let s = scratch("exec");
    let (repo, probe) = setup(&s);
    let k0 = key(&repo, &RS, &probe).unwrap();
    fs::set_permissions(repo.join("src/lib.rs"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(k0, key(&repo, &RS, &probe).unwrap());
}

/// Commits a `Cargo.toml` naming `dep` as a path dependency.
fn depend_on(repo: &Path, dep: &str) {
    fs::write(
        repo.join("Cargo.toml"),
        format!("[package]\nname = \"a\"\n\n[dependencies]\noutside = {{ path = \"{dep}\" }}\n"),
    )
    .unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "dep"]);
}

/// A crate directory with a `Cargo.toml` (extra lines appended) and `src/lib.rs`.
fn crate_dir(dir: &Path, manifest_tail: &str) {
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname = \"o\"\n{manifest_tail}"),
    )
    .unwrap();
    fs::write(dir.join("src/lib.rs"), "pub fn o() {}\n").unwrap();
}

const NO_CARGO: KeySpec = KeySpec {
    gate: "duplication",
    inputs: Inputs::Tree,
    env: &[],
    tools: &["git"],
    extra_paths: &[],
    ignored_inputs: &[],
    decl: "",
};

#[test]
fn an_out_of_tree_path_dependency_of_a_member_changes_a_cargo_key_only() {
    let s = scratch("outside");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("outside"), "");
    // A member's manifest, not the root's: the root's is part of the
    // runner's own build chain, which every key follows.
    crate_dir(
        &repo.join("m"),
        "\n[dependencies]\noutside = { path = \"../../outside\" }\n",
    );
    manifest_is(&repo, "[workspace]\nmembers = [\"m\"]\n");
    let (cargo0, plain0) = (
        key(&repo, &TREE, &probe).unwrap(),
        key(&repo, &NO_CARGO, &probe).unwrap(),
    );
    fs::write(s.0.join("outside/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(cargo0, key(&repo, &TREE, &probe).unwrap(), "cargo gate");
    assert_eq!(plain0, key(&repo, &NO_CARGO, &probe).unwrap(), "no cargo");
}

#[test]
fn an_out_of_tree_path_dependency_of_the_root_manifest_changes_every_key() {
    let s = scratch("outside-root");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("outside"), "");
    depend_on(&repo, "../outside");
    let plain0 = key(&repo, &NO_CARGO, &probe).unwrap();
    fs::write(s.0.join("outside/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(plain0, key(&repo, &NO_CARGO, &probe).unwrap());
}

#[test]
fn path_dependencies_of_an_outside_crate_are_followed() {
    let s = scratch("outside2");
    let (repo, probe) = setup(&s);
    crate_dir(
        &s.0.join("outside"),
        "\n[dependencies]\nnext = { path=\"../outside2\" }\n",
    );
    crate_dir(&s.0.join("outside2"), "");
    depend_on(&repo, "../outside");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("outside2/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn cargo_config_paths_outside_the_tree_are_fingerprinted() {
    let s = scratch("config-paths");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("patched"), "");
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(
        repo.join(".cargo/config.toml"),
        "paths = [\n  \"../patched\",\n]\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("patched/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_missing_path_dependency_keeps_the_key_and_its_appearance_changes_it() {
    let s = scratch("outside-missing");
    let (repo, probe) = setup(&s);
    depend_on(&repo, "../later");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap());
    crate_dir(&s.0.join("later"), "");
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_dependency_cycle_terminates() {
    let s = scratch("outside-cycle");
    let (repo, probe) = setup(&s);
    crate_dir(
        &s.0.join("outside"),
        "\n[dependencies]\nback = { path = \"../repo\" }\nself = { path = \".\" }\n",
    );
    depend_on(&repo, "../outside");
    assert!(key(&repo, &TREE, &probe).is_ok());
}

/// `TREE` (a cargo gate) with these declarations.
fn tree_with<'a>(extra_paths: &'a [&'a str], ignored_inputs: &'a [&'a str]) -> KeySpec<'a> {
    KeySpec {
        extra_paths,
        ignored_inputs,
        ..TREE
    }
}

#[test]
fn editing_a_file_under_a_declared_extra_directory_changes_the_key() {
    let s = scratch("extra-dir");
    let (repo, probe) = setup(&s);
    let ext = s.0.join("ext");
    fs::create_dir_all(ext.join("sub")).unwrap();
    fs::write(ext.join("sub/data.txt"), "v1").unwrap();
    let abs = ext.to_str().unwrap();
    for entries in [&[abs][..], &["../ext"][..]] {
        let spec = KeySpec {
            extra_paths: entries,
            ..RS
        };
        let k0 = key(&repo, &spec, &probe).unwrap();
        fs::write(ext.join("sub/data.txt"), format!("{entries:?}")).unwrap();
        assert_ne!(k0, key(&repo, &spec, &probe).unwrap(), "{entries:?}");
    }
}

#[test]
fn a_missing_extra_path_keeps_the_key_and_its_creation_changes_it() {
    let s = scratch("extra-missing");
    let (repo, probe) = setup(&s);
    let spec = tree_with(&["../later.txt"], &[]);
    let k0 = key(&repo, &spec, &probe).unwrap();
    assert_eq!(k0, key(&repo, &spec, &probe).unwrap());
    fs::write(s.0.join("later.txt"), "x").unwrap();
    assert_ne!(k0, key(&repo, &spec, &probe).unwrap());
}

#[test]
fn a_tilde_extra_path_resolves_against_the_probe_home() {
    let s = scratch("extra-home");
    let (repo, probe) = setup(&s);
    let spec = tree_with(&["~/data.txt"], &[]);
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::create_dir_all(s.0.join("home")).unwrap();
    fs::write(s.0.join("home/data.txt"), "v1").unwrap();
    let k1 = key(&repo, &spec, &probe).unwrap();
    assert_ne!(k0, k1, "created");
    fs::write(s.0.join("home/data.txt"), "v2").unwrap();
    assert_ne!(k1, key(&repo, &spec, &probe).unwrap(), "edited");
}

#[test]
fn a_virtual_file_is_fingerprinted_by_its_content() {
    // /proc files report size 0, so hashing by path reads nothing.
    const PATH: &str = "/proc/sys/kernel/osrelease";
    let s = scratch("extra-proc");
    let (repo, probe) = setup(&s);
    let content = fs::read(PATH).unwrap();
    assert_ne!(content.len(), 0);
    let mut child = std::process::Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), &content).unwrap();
    let out = child.wait_with_output().unwrap();
    let blob = String::from_utf8(out.stdout).unwrap();
    let spec = tree_with(&[PATH], &[]);
    let m = manifest(&repo, &spec, &probe).unwrap();
    let line = m.lines().find(|l| l.contains(PATH)).unwrap();
    assert!(line.contains(blob.trim()), "{line}");
}

#[test]
fn declared_ignored_inputs_join_the_key_and_other_ignored_files_do_not() {
    let s = scratch("ignored");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(repo.join("out")).unwrap();
    fs::write(repo.join("out/a.gen"), "v1").unwrap();
    fs::write(repo.join("out/b.log"), "v1").unwrap();
    let spec = tree_with(&[], &["out/*.gen"]);
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::write(repo.join("out/b.log"), "v2").unwrap();
    assert_eq!(k0, key(&repo, &spec, &probe).unwrap(), "not declared");
    fs::write(repo.join("out/a.gen"), "v2").unwrap();
    assert_ne!(k0, key(&repo, &spec, &probe).unwrap(), "declared");
}

#[test]
fn cache_env_txt_adds_variables_to_every_key() {
    let s = scratch("cache-env");
    let (repo, mut probe) = setup(&s);
    fs::create_dir_all(repo.join("gates")).unwrap();
    fs::write(
        repo.join("gates/cache-env.txt"),
        "# variables tests read\n\n  MY_TEST_VAR  \nRUSTFLAGS\n",
    )
    .unwrap();
    let k0 = key(&repo, &RS, &probe).unwrap();
    probe.vars.insert("MY_TEST_VAR".into(), "1".into());
    let k1 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k0, k1, "listed variable on a narrowed gate");
    probe.vars.insert("UNLISTED".into(), "1".into());
    assert_eq!(k1, key(&repo, &RS, &probe).unwrap(), "unlisted variable");
    fs::write(repo.join("gates/cache-env.txt"), "MY_TEST_VAR\n# more\n").unwrap();
    assert_ne!(k1, key(&repo, &RS, &probe).unwrap(), "the list itself");
}

#[test]
fn configuration_in_ancestor_directories_changes_a_cargo_key_only() {
    let s = scratch("config-ancestor");
    let (repo, probe) = setup(&s);
    let (cargo0, plain0) = (
        key(&repo, &TREE, &probe).unwrap(),
        key(&repo, &NO_CARGO, &probe).unwrap(),
    );
    fs::write(
        s.0.join("clippy.toml"),
        "too-many-arguments-threshold = 3\n",
    )
    .unwrap();
    let cargo1 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(cargo0, cargo1, "created");
    fs::write(
        s.0.join("clippy.toml"),
        "too-many-arguments-threshold = 4\n",
    )
    .unwrap();
    assert_ne!(cargo1, key(&repo, &TREE, &probe).unwrap(), "edited");
    assert_eq!(plain0, key(&repo, &NO_CARGO, &probe).unwrap(), "no cargo");
}

#[test]
fn cargo_home_configuration_changes_every_key_and_rustfmt_user_configuration_a_cargo_key_only() {
    let s = scratch("config-home");
    let (repo, mut probe) = setup(&s);
    let fake = s.0.join("cargo-home");
    fs::create_dir_all(&fake).unwrap();
    fs::write(fake.join("config.toml"), "[build]\njobs = 1\n").unwrap();
    probe
        .vars
        .insert("CARGO_HOME".into(), fake.to_str().unwrap().into());
    let (cargo0, plain0) = (
        key(&repo, &TREE, &probe).unwrap(),
        key(&repo, &NO_CARGO, &probe).unwrap(),
    );
    fs::write(fake.join("config.toml"), "[build]\njobs = 2\n").unwrap();
    let (cargo1, plain1) = (
        key(&repo, &TREE, &probe).unwrap(),
        key(&repo, &NO_CARGO, &probe).unwrap(),
    );
    assert_ne!(cargo0, cargo1, "$CARGO_HOME/config.toml");
    // Cargo builds the runner with that configuration.
    assert_ne!(plain0, plain1, "$CARGO_HOME/config.toml, no cargo");
    // Without XDG_CONFIG_HOME, rustfmt's user config lives under ~/.config.
    fs::create_dir_all(s.0.join("home/.config/rustfmt")).unwrap();
    fs::write(s.0.join("home/.config/rustfmt/rustfmt.toml"), "x").unwrap();
    let cargo2 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(cargo1, cargo2, "~/.config/rustfmt/rustfmt.toml");
    assert_eq!(
        plain1,
        key(&repo, &NO_CARGO, &probe).unwrap(),
        "rustfmt, no cargo"
    );
    // Without CARGO_HOME, cargo's home is ~/.cargo.
    probe.vars.remove("CARGO_HOME");
    let (cargo3, plain3) = (
        key(&repo, &TREE, &probe).unwrap(),
        key(&repo, &NO_CARGO, &probe).unwrap(),
    );
    fs::create_dir_all(s.0.join("home/.cargo")).unwrap();
    fs::write(s.0.join("home/.cargo/config"), "x").unwrap();
    assert_ne!(
        cargo3,
        key(&repo, &TREE, &probe).unwrap(),
        "~/.cargo/config"
    );
    assert_ne!(
        plain3,
        key(&repo, &NO_CARGO, &probe).unwrap(),
        "~/.cargo/config, no cargo"
    );
}

/// Commits `Cargo.toml` with this content.
fn manifest_is(repo: &Path, text: &str) {
    fs::write(repo.join("Cargo.toml"), text).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "manifest"]);
}

#[test]
fn an_outside_build_script_fingerprints_its_whole_directory() {
    let s = scratch("outside-build");
    let (repo, probe) = setup(&s);
    let ext = s.0.join("ext");
    fs::create_dir_all(&ext).unwrap();
    fs::write(ext.join("build.rs"), "fn main() {}\n").unwrap();
    fs::write(ext.join("helper.rs"), "// v1\n").unwrap();
    manifest_is(
        &repo,
        "[package]\nname = \"a\"\nbuild = \"../ext/build.rs\"\nworkspace = true\n",
    );
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(ext.join("helper.rs"), "// v2\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_quoted_path_key_is_discovered() {
    let s = scratch("outside-quoted");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("q"), "");
    manifest_is(
        &repo,
        "[package]\nname = \"a\"\n\n[dependencies.q]\n\"path\" = \"../q\"\n",
    );
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("q/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_vendored_source_directory_is_discovered() {
    let s = scratch("outside-vendor");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("vendor/dep"), "");
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(
        repo.join(".cargo/config.toml"),
        "[source.vendored]\ndirectory = \"../vendor\"\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("vendor/dep/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn an_outside_directory_containing_the_repository_makes_the_key_an_error() {
    let s = scratch("outside-parent");
    let (repo, probe) = setup(&s);
    depend_on(&repo, "..");
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains("contains the repository"), "{err}");
    let spec = KeySpec {
        extra_paths: &[".."],
        ..RS
    };
    let err = key(&repo, &spec, &probe).unwrap_err();
    assert!(err.contains("contains the repository"), "{err}");
}

#[test]
fn non_utf8_file_names_are_fingerprinted() {
    use std::os::unix::ffi::OsStrExt as _;
    let s = scratch("non-utf8");
    let (repo, probe) = setup(&s);
    let name = std::ffi::OsStr::from_bytes(b"bad\xff.rs");
    crate_dir(&s.0.join("outside"), "");
    depend_on(&repo, "../outside");
    let outside_file = s.0.join("outside/src").join(name);
    fs::write(&outside_file, "v1").unwrap();
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(&outside_file, "v2").unwrap();
    let k1 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(k0, k1, "outside");
    let tree_file = repo.join("src").join(name);
    fs::write(&tree_file, "v1").unwrap();
    let k2 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(k1, k2, "in the tree, created");
    fs::write(&tree_file, "v2").unwrap();
    assert_ne!(
        k2,
        key(&repo, &TREE, &probe).unwrap(),
        "in the tree, edited"
    );
}

#[test]
fn paths_named_by_an_ancestor_cargo_config_are_followed() {
    let s = scratch("config-follow-ancestor");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("ovr"), "");
    fs::create_dir_all(s.0.join(".cargo")).unwrap();
    let abs = s.0.join("ovr");
    fs::write(
        s.0.join(".cargo/config.toml"),
        format!("paths = [\"{}\"]\n", abs.display()),
    )
    .unwrap();
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(abs.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn paths_named_by_the_cargo_home_config_resolve_from_its_parent() {
    let s = scratch("config-follow-home");
    let (repo, mut probe) = setup(&s);
    crate_dir(&s.0.join("ovr2"), "");
    let cargo_home = s.0.join("ch");
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(cargo_home.join("config.toml"), "paths = [\"ovr2\"]\n").unwrap();
    probe
        .vars
        .insert("CARGO_HOME".into(), cargo_home.to_str().unwrap().into());
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("ovr2/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn hidden_target_and_symlinked_files_under_an_extra_directory_count() {
    let s = scratch("extra-full");
    let (repo, probe) = setup(&s);
    let ext = s.0.join("ext");
    fs::create_dir_all(ext.join(".hidden")).unwrap();
    fs::create_dir_all(ext.join("target")).unwrap();
    fs::write(ext.join(".hidden/a"), "v1").unwrap();
    fs::write(ext.join("target/b"), "v1").unwrap();
    fs::write(s.0.join("real.txt"), "v1").unwrap();
    std::os::unix::fs::symlink(s.0.join("real.txt"), ext.join("link")).unwrap();
    let spec = tree_with(&["../ext"], &[]);
    for edited in [
        ext.join(".hidden/a"),
        ext.join("target/b"),
        s.0.join("real.txt"),
    ] {
        let k0 = key(&repo, &spec, &probe).unwrap();
        fs::write(&edited, "v2").unwrap();
        assert_ne!(
            k0,
            key(&repo, &spec, &probe).unwrap(),
            "{}",
            edited.display()
        );
    }
}

#[test]
fn a_symlinked_directory_under_an_extra_or_outside_directory_is_an_error() {
    let s = scratch("symlinked-dir");
    let (repo, probe) = setup(&s);
    let ext = s.0.join("ext");
    fs::create_dir_all(s.0.join("elsewhere")).unwrap();
    fs::create_dir_all(&ext).unwrap();
    std::os::unix::fs::symlink(s.0.join("elsewhere"), ext.join("dirlink")).unwrap();
    let err = key(&repo, &tree_with(&["../ext"], &[]), &probe).unwrap_err();
    assert!(err.contains("symlinked directory"), "{err}");
    crate_dir(&s.0.join("outside"), "");
    std::os::unix::fs::symlink(s.0.join("elsewhere"), s.0.join("outside/src/dirlink")).unwrap();
    depend_on(&repo, "../outside");
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains("symlinked directory"), "{err}");
}

#[test]
fn a_symlinked_file_in_an_outside_dependency_counts() {
    let s = scratch("outside-link");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("outside"), "");
    fs::write(s.0.join("real.rs"), "// v1\n").unwrap();
    std::os::unix::fs::symlink(s.0.join("real.rs"), s.0.join("outside/src/link.rs")).unwrap();
    depend_on(&repo, "../outside");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("real.rs"), "// v2\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_multi_line_string_path_is_discovered() {
    let s = scratch("outside-multiline");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("q"), "");
    manifest_is(
        &repo,
        "[package]\nname = \"a\"\n\n[dependencies.q]\npath = '''../q'''\n",
    );
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("q/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn an_extra_path_that_is_neither_file_nor_directory_is_an_error() {
    let s = scratch("extra-fifo");
    let (repo, probe) = setup(&s);
    let fifo = s.0.join("fifo");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|st| st.success()) {
        eprintln!("skipped: mkfifo unavailable");
        return;
    }
    let err = key(&repo, &tree_with(&["../fifo"], &[]), &probe).unwrap_err();
    assert!(err.contains("not a regular file or directory"), "{err}");
}

#[test]
fn ignored_inputs_with_a_leading_wildcard_still_match() {
    let s = scratch("ignored-wild");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(repo.join("out/deep")).unwrap();
    fs::write(repo.join("out/deep/a.gen"), "v1").unwrap();
    let spec = tree_with(&[], &["**/*.gen"]);
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::write(repo.join("out/deep/a.gen"), "v2").unwrap();
    assert_ne!(k0, key(&repo, &spec, &probe).unwrap());
}

#[test]
fn a_rustfmt_config_in_home_changes_a_cargo_key() {
    let s = scratch("home-rustfmt");
    let (repo, probe) = setup(&s);
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::create_dir_all(s.0.join("home")).unwrap();
    fs::write(s.0.join("home/.rustfmt.toml"), "max_width = 80\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn relative_paths_in_an_ancestor_cargo_config_resolve_from_the_directory_holding_cargo() {
    let s = scratch("config-follow-relative");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("ovr"), "");
    fs::create_dir_all(s.0.join(".cargo")).unwrap();
    fs::write(s.0.join(".cargo/config.toml"), "paths = [\"ovr\"]\n").unwrap();
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("ovr/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_non_canonical_root_gives_the_canonical_key_and_bounds() {
    let s = scratch("non-canonical-root");
    let (repo, probe) = setup(&s);
    // The symlink lives outside the repository's parent, so a root that is
    // not canonicalized has different ancestors and escapes the bound.
    let other = scratch("non-canonical-root-link");
    let link = other.0.join("link");
    std::os::unix::fs::symlink(&repo, &link).unwrap();
    let dotted = s.0.join(".").join("repo");
    let extra = tree_with(&["../ext"], &[]);
    fs::create_dir_all(s.0.join("ext")).unwrap();
    fs::write(s.0.join("ext/a"), "x").unwrap();
    // Seen only through the canonical root's ancestors.
    fs::write(s.0.join("clippy.toml"), "x").unwrap();
    let canonical = key(&repo, &extra, &probe).unwrap();
    for root in [&dotted, &link] {
        assert_eq!(
            canonical,
            key(root, &extra, &probe).unwrap(),
            "{}",
            root.display()
        );
    }
    let parent = KeySpec {
        extra_paths: &[".."],
        ..NO_CARGO
    };
    depend_on(&repo, "..");
    for root in [&repo, &dotted, &link] {
        for spec in [&TREE, &parent] {
            let err = key(root, spec, &probe).unwrap_err();
            assert!(
                err.contains("contains the repository"),
                "{}: {err}",
                root.display()
            );
        }
    }
}

#[test]
fn cargo_and_rust_prefixed_variables_change_every_key() {
    let s = scratch("env-prefix");
    let (repo, mut probe) = setup(&s);
    let (cargo0, plain0) = (
        key(&repo, &TREE, &probe).unwrap(),
        key(&repo, &NO_CARGO, &probe).unwrap(),
    );
    probe.vars.insert("MY_UNDECLARED".into(), "1".into());
    assert_eq!(cargo0, key(&repo, &TREE, &probe).unwrap(), "unprefixed");
    assert_eq!(
        plain0,
        key(&repo, &NO_CARGO, &probe).unwrap(),
        "unprefixed, no cargo"
    );
    probe
        .vars
        .insert("CARGO_PROFILE_TEST_OVERFLOW_CHECKS".into(), "false".into());
    assert_ne!(cargo0, key(&repo, &TREE, &probe).unwrap(), "CARGO_ prefix");
    // Cargo builds the runner, so a gate that does not run cargo keys it too.
    assert_ne!(plain0, key(&repo, &NO_CARGO, &probe).unwrap(), "no cargo");
    probe.vars.remove("CARGO_PROFILE_TEST_OVERFLOW_CHECKS");
    assert_eq!(cargo0, key(&repo, &TREE, &probe).unwrap(), "unset again");
    probe.vars.insert("RUST_MIN_STACK".into(), "1".into());
    assert_ne!(cargo0, key(&repo, &TREE, &probe).unwrap(), "RUST prefix");
}

#[test]
fn a_non_utf8_rustflags_value_is_keyed() {
    use std::os::unix::ffi::OsStrExt as _;
    let s = scratch("env-non-utf8");
    let (repo, mut probe) = setup(&s);
    let unset = key(&repo, &TREE, &probe).unwrap();
    let flags = |bytes: &[u8]| std::ffi::OsStr::from_bytes(bytes).to_os_string();
    probe
        .vars
        .insert("RUSTFLAGS".into(), flags(b"-C opt-level=\xff"));
    let k1 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(unset, k1, "set");
    probe
        .vars
        .insert("RUSTFLAGS".into(), flags(b"-C opt-level=\xfe"));
    assert_ne!(k1, key(&repo, &TREE, &probe).unwrap(), "another value");
}

#[test]
fn a_path_dependency_inside_an_ignored_directory_is_fingerprinted() {
    let s = scratch("ignored-dep");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n/gen\n").unwrap();
    crate_dir(&repo.join("gen/q"), "");
    fs::create_dir_all(repo.join("gen/q/target/debug")).unwrap();
    fs::write(repo.join("gen/q/target/CACHEDIR.TAG"), "Signature").unwrap();
    fs::write(repo.join("gen/q/target/debug/out"), "v1").unwrap();
    depend_on(&repo, "gen/q");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("gen/q/target/debug/out"), "v2").unwrap();
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap(), "build output");
    fs::write(repo.join("gen/q/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap(), "source");
}

#[test]
fn a_member_dependency_inside_an_ignored_directory_is_fingerprinted() {
    let s = scratch("ignored-dep-member");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n/gen\n").unwrap();
    crate_dir(&repo.join("gen/q"), "");
    crate_dir(
        &repo.join("member"),
        "\n[dependencies]\nq = { path = \"../gen/q\" }\n",
    );
    manifest_is(&repo, "[workspace]\nmembers = [\"member\"]\n");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("gen/q/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn workspace_members_outside_the_root_are_followed() {
    let s = scratch("members-outside");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("om"), "");
    manifest_is(
        &repo,
        "[workspace]\nmembers = [\"../om\"]\ndefault-members = [\"../om\"]\n",
    );
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("om/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_member_glob_pointing_outside_the_root_makes_the_key_an_error() {
    let s = scratch("members-glob");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("x/a"), "");
    manifest_is(&repo, "[workspace]\nmembers = [\"crates/*\"]\n");
    assert!(key(&repo, &TREE, &probe).is_ok(), "glob inside the root");
    manifest_is(&repo, "[workspace]\nmembers = [\"../x/*\"]\n");
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(
        err.contains("glob pointing outside the repository"),
        "{err}"
    );
}

#[test]
fn a_local_registry_outside_the_root_is_followed() {
    let s = scratch("local-registry");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(s.0.join("reg")).unwrap();
    fs::write(s.0.join("reg/dep-1.0.0.crate"), "v1").unwrap();
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(
        repo.join(".cargo/config.toml"),
        "[source.l]\nlocal-registry = \"../reg\"\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("reg/dep-1.0.0.crate"), "v2").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn no_home_makes_a_cargo_key_and_a_tilde_extra_path_an_error() {
    let s = scratch("no-home");
    let (repo, mut probe) = setup(&s);
    probe.home = None;
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains("HOME is unset or empty"), "cargo gate: {err}");
    let tilde = KeySpec {
        extra_paths: &["~/data.txt"],
        ..NO_CARGO
    };
    let err = key(&repo, &tilde, &probe).unwrap_err();
    assert!(err.contains("HOME is unset or empty"), "~/ entry: {err}");
    // Cargo builds the runner and reads the user's config for it, so even a
    // gate that does not run cargo has no key without HOME.
    let err = key(&repo, &NO_CARGO, &probe).unwrap_err();
    assert!(err.contains("HOME is unset or empty"), "no cargo: {err}");
}

#[test]
fn an_outside_walk_skips_only_git_and_tagged_build_output() {
    let s = scratch("outside-skip");
    let (repo, probe) = setup(&s);
    let dep = s.0.join("outside");
    crate_dir(&dep, "");
    fs::create_dir_all(dep.join("src/target")).unwrap();
    fs::create_dir_all(dep.join(".data")).unwrap();
    fs::create_dir_all(dep.join("target/debug")).unwrap();
    fs::write(dep.join("target/CACHEDIR.TAG"), "Signature").unwrap();
    fs::write(dep.join("target/debug/out"), "v1").unwrap();
    fs::write(dep.join("src/target/mod.rs"), "// v1\n").unwrap();
    fs::write(dep.join(".data/x"), "v1").unwrap();
    depend_on(&repo, "../outside");
    for edited in ["src/target/mod.rs", ".data/x"] {
        let k0 = key(&repo, &TREE, &probe).unwrap();
        fs::write(dep.join(edited), "v2").unwrap();
        assert_ne!(k0, key(&repo, &TREE, &probe).unwrap(), "{edited}");
    }
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(dep.join("target/debug/out"), "v2").unwrap();
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap(), "tagged target");
}

#[test]
fn binaries_named_by_the_environment_are_fingerprinted() {
    let s = scratch("named-env");
    let (repo, mut probe) = setup(&s);
    let wrapper = s.0.join("wrap.sh");
    write_exe(&wrapper, "#!/bin/sh\nexec \"$@\"\n");
    probe
        .vars
        .insert("RUSTC_WRAPPER".into(), wrapper.clone().into_os_string());
    let k0 = key(&repo, &RS, &probe).unwrap();
    write_exe(&wrapper, "#!/bin/sh\necho wrapped; exec \"$@\"\n");
    let k1 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k0, k1, "absolute path rewritten");
    // A bare name resolves through PATH; a missing one is recorded.
    probe.vars.insert("RUSTC_WRAPPER".into(), "sccache".into());
    let k2 = key(&repo, &RS, &probe).unwrap();
    write_exe(&s.0.join("bin/sccache"), "#!/bin/sh\n");
    let k3 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k2, k3, "bare name appears on PATH");
    write_exe(&s.0.join("bin/sccache"), "#!/bin/sh\n# another build\n");
    assert_ne!(k3, key(&repo, &RS, &probe).unwrap(), "bare name rewritten");
}

#[test]
fn binaries_named_by_cargo_configuration_are_fingerprinted() {
    let s = scratch("named-config");
    let (repo, probe) = setup(&s);
    write_exe(&repo.join("ld.sh"), "#!/bin/sh\n");
    write_exe(&repo.join("run.sh"), "#!/bin/sh\n");
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(
        repo.join(".cargo/config.toml"),
        "[target.x86_64-unknown-linux-gnu]\nlinker = \"./ld.sh\"\nrunner = [\"./run.sh\", \"--x\"]\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    for edited in ["ld.sh", "run.sh"] {
        let k0 = key(&repo, &RS, &probe).unwrap();
        write_exe(&repo.join(edited), "#!/bin/sh\n# edited\n");
        assert_ne!(k0, key(&repo, &RS, &probe).unwrap(), "{edited}");
    }
}

#[test]
fn rustfmt_configuration_above_an_outside_directory_changes_a_cargo_key() {
    let s = scratch("outside-rustfmt");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("o/x"), "");
    fs::write(s.0.join("o/rustfmt.toml"), "max_width = 80\n").unwrap();
    depend_on(&repo, "../o/x");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("o/rustfmt.toml"), "max_width = 90\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_glob_member_inside_an_ignored_directory_is_fingerprinted() {
    let s = scratch("glob-ignored");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n/gen\n").unwrap();
    crate_dir(&repo.join("gen/r"), "");
    manifest_is(&repo, "[workspace]\nmembers = [\"gen/*\"]\n");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("gen/r/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_glob_member_symlinked_outside_the_root_is_followed() {
    let s = scratch("glob-symlink");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("ext"), "");
    fs::create_dir_all(repo.join("crates")).unwrap();
    std::os::unix::fs::symlink("../../ext", repo.join("crates/ext")).unwrap();
    manifest_is(&repo, "[workspace]\nmembers = [\"crates/*\"]\n");
    // A tracked directory symlink makes a whole-tree key an error, so use
    // a narrowed cargo gate (fmt's shape).
    let k0 = key(&repo, &RS, &probe).unwrap();
    fs::write(s.0.join("ext/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &RS, &probe).unwrap());
}

#[test]
fn binaries_named_by_cargo_environment_forms_are_fingerprinted() {
    let s = scratch("named-cargo-env");
    let (repo, mut probe) = setup(&s);
    let script = s.0.join("tool.sh");
    for (name, value) in [
        ("RUSTDOC", script.clone().into_os_string()),
        (
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            script.clone().into_os_string(),
        ),
        ("CARGO_BUILD_RUSTC_WRAPPER", script.clone().into_os_string()),
        ("CARGO_HOST_LINKER", script.clone().into_os_string()),
        (
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            OsString::from(format!("{} --flag", script.display())),
        ),
    ] {
        write_exe(&script, "#!/bin/sh\n");
        probe.vars.clear();
        probe.vars.insert(name.into(), value);
        let k0 = key(&repo, &RS, &probe).unwrap();
        write_exe(&script, &format!("#!/bin/sh\n# rewritten for {name}\n"));
        assert_ne!(k0, key(&repo, &RS, &probe).unwrap(), "{name}");
    }
}

#[test]
fn variables_cargo_sets_for_the_runner_itself_are_not_keyed() {
    let s = scratch("env-cargo-run");
    let (repo, mut probe) = setup(&s);
    let k0 = key(&repo, &TREE, &probe).unwrap();
    for (name, value) in [
        ("CARGO_MANIFEST_DIR", "/wt2/xtask"),
        ("CARGO_MANIFEST_PATH", "/wt2/xtask/Cargo.toml"),
        ("CARGO_PKG_NAME", "xtask"),
        ("CARGO_PKG_VERSION", "0.1.0"),
        ("CARGO_CRATE_NAME", "xtask"),
        ("CARGO_BIN_NAME", "xtask"),
        ("CARGO_BIN_EXE_xtask", "/wt2/target/debug/xtask"),
        ("CARGO_PRIMARY_PACKAGE", "1"),
        ("CARGO_TARGET_TMPDIR", "/wt2/target/tmp"),
        ("CARGO", "/usr/bin/cargo"),
        ("RUST_RECURSION_COUNT", "1"),
    ] {
        probe.vars.insert(name.into(), value.into());
    }
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap(), "cargo run's own");
    probe
        .vars
        .insert("CARGO_PROFILE_DEV_DEBUG".into(), "0".into());
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap(), "CARGO_PROFILE_*");
}

#[test]
fn ignored_rustfmt_configuration_above_an_ignored_dependency_is_fingerprinted() {
    let s = scratch("ignored-rustfmt");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n/gen\n").unwrap();
    crate_dir(&repo.join("gen/q"), "");
    fs::write(repo.join("gen/rustfmt.toml"), "max_width = 80\n").unwrap();
    depend_on(&repo, "gen/q");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("gen/rustfmt.toml"), "max_width = 90\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn an_in_tree_file_value_lists_only_that_file() {
    // A member's `build` names a listed file in another directory: only that
    // file counts, not the ignored files beside it. (A root package's own
    // directory is the root, whose ignored files all count.)
    let s = scratch("in-tree-file");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\ntools/scratch.txt\n").unwrap();
    fs::create_dir_all(repo.join("tools")).unwrap();
    fs::write(repo.join("tools/build.rs"), "fn main() {}\n").unwrap();
    crate_dir(&repo.join("m"), "build = \"../tools/build.rs\"\n");
    manifest_is(&repo, "[workspace]\nmembers = [\"m\"]\n");
    fs::write(repo.join("tools/scratch.txt"), "v1").unwrap();
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("tools/scratch.txt"), "v2").unwrap();
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_runner_array_keeps_a_first_element_with_spaces_verbatim() {
    let s = scratch("runner-array-spaces");
    let (repo, probe) = setup(&s);
    let dir = s.0.join("my tools");
    fs::create_dir_all(&dir).unwrap();
    let script = dir.join("run.sh");
    write_exe(&script, "#!/bin/sh\n");
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(
        repo.join(".cargo/config.toml"),
        format!(
            "[target.x86_64-unknown-linux-gnu]\nrunner = [\"{}\", \"--x\"]\n",
            script.display()
        ),
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    let k0 = key(&repo, &RS, &probe).unwrap();
    write_exe(&script, "#!/bin/sh\n# rewritten\n");
    assert_ne!(k0, key(&repo, &RS, &probe).unwrap());
}

/// fmt's own declaration, as the registry has it.
fn fmt_gate() -> xtask::Gate {
    xtask::registry()
        .into_iter()
        .find(|g| g.name == "fmt")
        .unwrap()
}

#[test]
fn a_deep_symlink_below_a_glob_member_prefix_is_followed() {
    let s = scratch("glob-deep-symlink");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("ext"), "");
    fs::create_dir_all(repo.join("crates/a")).unwrap();
    std::os::unix::fs::symlink("../../../ext", repo.join("crates/a/x")).unwrap();
    manifest_is(&repo, "[workspace]\nmembers = [\"crates/*/x\"]\n");
    let fmt = fmt_gate();
    for (label, spec) in [("narrowed", RS), ("registry fmt", fmt.key_spec())] {
        let k0 = key(&repo, &spec, &probe).unwrap();
        let edit = format!("pub fn changed_for_{}() {{}}\n", label.len());
        fs::write(s.0.join("ext/src/lib.rs"), edit).unwrap();
        assert_ne!(k0, key(&repo, &spec, &probe).unwrap(), "{label}");
    }
}

#[test]
fn a_dangling_symlink_below_a_glob_member_prefix_makes_the_key_an_error() {
    let s = scratch("glob-dangling");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(repo.join("crates")).unwrap();
    std::os::unix::fs::symlink("../../nowhere", repo.join("crates/gone")).unwrap();
    manifest_is(&repo, "[workspace]\nmembers = [\"crates/*\"]\n");
    let err = key(&repo, &RS, &probe).unwrap_err();
    assert!(err.contains("dangling symlink"), "{err}");
}

#[test]
fn an_ignored_in_tree_file_target_fingerprints_its_ignored_siblings() {
    let s = scratch("ignored-file-target");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n/gen\n").unwrap();
    fs::create_dir_all(repo.join("gen")).unwrap();
    fs::write(repo.join("gen/lib.rs"), "mod foo;\n").unwrap();
    fs::write(repo.join("gen/foo.rs"), "// v1\n").unwrap();
    manifest_is(
        &repo,
        "[package]\nname = \"a\"\n\n[lib]\npath = \"gen/lib.rs\"\n",
    );
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("gen/foo.rs"), "// v2\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_glob_member_symlinked_into_an_ignored_directory_is_fingerprinted() {
    let s = scratch("glob-symlink-ignored");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n/gen\n").unwrap();
    crate_dir(&repo.join("gen/a"), "");
    fs::create_dir_all(repo.join("crates")).unwrap();
    std::os::unix::fs::symlink("../gen/a", repo.join("crates/a")).unwrap();
    manifest_is(&repo, "[workspace]\nmembers = [\"crates/*\"]\n");
    let fmt = fmt_gate();
    let spec = fmt.key_spec();
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::write(
        repo.join("gen/a/src/lib.rs"),
        "pub   fn misformatted() {}\n",
    )
    .unwrap();
    assert_ne!(k0, key(&repo, &spec, &probe).unwrap());
}

/// Commits `.cargo/config.toml` with this content.
fn cargo_config_is(repo: &Path, text: &str) {
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(repo.join(".cargo/config.toml"), text).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "config"]);
}

#[test]
fn an_outside_file_included_by_a_cargo_config_array_is_fingerprinted() {
    let s = scratch("include-array");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(s.0.join("shared")).unwrap();
    fs::write(s.0.join("shared/cargo.toml"), "[env]\nX = \"1\"\n").unwrap();
    // Relative to the including file's own directory (`repo/.cargo`).
    cargo_config_is(&repo, "include = [\"../../shared/cargo.toml\"]\n");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("shared/cargo.toml"), "[env]\nX = \"2\"\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn an_outside_file_included_by_an_include_table_is_fingerprinted() {
    let s = scratch("include-table");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(s.0.join("shared")).unwrap();
    fs::write(s.0.join("shared/t.toml"), "[env]\nX = \"1\"\n").unwrap();
    cargo_config_is(&repo, "[[include]]\npath = \"../../shared/t.toml\"\n");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("shared/t.toml"), "[env]\nX = \"2\"\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn an_ignored_optional_include_in_the_tree_is_fingerprinted() {
    let s = scratch("include-optional");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n.cargo/local.toml\n").unwrap();
    cargo_config_is(
        &repo,
        "include = [{ path = \"local.toml\", optional = true }]\n",
    );
    let k0 = key(&repo, &TREE, &probe).unwrap();
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap(), "missing: stable");
    fs::write(repo.join(".cargo/local.toml"), "[env]\nX = \"1\"\n").unwrap();
    let k1 = key(&repo, &TREE, &probe).unwrap();
    assert_ne!(k0, k1, "created");
    fs::write(repo.join(".cargo/local.toml"), "[env]\nX = \"2\"\n").unwrap();
    assert_ne!(k1, key(&repo, &TREE, &probe).unwrap(), "edited");
}

#[test]
fn a_nested_include_is_followed() {
    let s = scratch("include-nested");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(s.0.join("shared/more")).unwrap();
    fs::write(s.0.join("shared/a.toml"), "include = \"more/b.toml\"\n").unwrap();
    fs::write(s.0.join("shared/more/b.toml"), "[env]\nX = \"1\"\n").unwrap();
    cargo_config_is(&repo, "include = [\"../../shared/a.toml\"]\n");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("shared/more/b.toml"), "[env]\nX = \"2\"\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn paths_named_by_an_included_file_are_followed() {
    let s = scratch("include-paths");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("ovr"), "");
    fs::create_dir_all(s.0.join("shared")).unwrap();
    // An included file's paths resolve, like any config file's, from the
    // parent of its directory: `shared/..`. Checked with cargo 1.99: a
    // `.cargo/sub/inc.toml` included from `.cargo/config.toml` with
    // `paths = ["ovr"]` makes cargo look for `.cargo/ovr`.
    fs::write(s.0.join("shared/p.toml"), "paths = [\"ovr\"]\n").unwrap();
    cargo_config_is(&repo, "include = [\"../../shared/p.toml\"]\n");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(s.0.join("ovr/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_directory_symlink_below_a_plain_member_is_followed() {
    let s = scratch("member-symlink");
    let (repo, probe) = setup(&s);
    let ext = s.0.join("ext");
    fs::create_dir_all(&ext).unwrap();
    fs::write(ext.join("mod.rs"), "pub fn a() {}\n").unwrap();
    crate_dir(&repo.join("m"), "");
    std::os::unix::fs::symlink("../../../ext", repo.join("m/src/gen")).unwrap();
    manifest_is(&repo, "[workspace]\nmembers = [\"m\"]\n");
    let fmt = fmt_gate();
    let spec = fmt.key_spec();
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::write(ext.join("mod.rs"), "pub   fn misformatted() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &spec, &probe).unwrap());
}

#[test]
fn a_tracked_file_named_by_a_path_attribute_is_fingerprinted() {
    let s = scratch("path-attr");
    let (repo, probe) = setup(&s);
    fs::write(repo.join("src/lib.rs"), "#[path = \"x.inc\"]\nmod x;\n").unwrap();
    fs::write(repo.join("src/x.inc"), "pub fn x() {}\n").unwrap();
    git(&repo, &["add", "-A"]);
    let fmt = fmt_gate();
    let spec = fmt.key_spec();
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::write(repo.join("src/x.inc"), "pub   fn misformatted() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &spec, &probe).unwrap());
}

#[test]
fn ignored_outside_and_missing_path_attribute_targets_change_the_key() {
    let s = scratch("path-attr-other");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n/gen\n").unwrap();
    fs::create_dir_all(repo.join("gen")).unwrap();
    fs::write(repo.join("gen/g.rs"), "// v1\n").unwrap();
    fs::create_dir_all(s.0.join("ext")).unwrap();
    fs::write(s.0.join("ext/e.rs"), "// v1\n").unwrap();
    fs::write(
        repo.join("src/lib.rs"),
        "#[path = \"../gen/g.rs\"]\nmod g;\n#[cfg_attr(unix, path = \"../../ext/e.rs\")]\nmod e;\n#[path = \"later.rs\"]\nmod later;\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    let fmt = fmt_gate();
    let spec = fmt.key_spec();
    let mut k = key(&repo, &spec, &probe).unwrap();
    for (file, label) in [
        (repo.join("gen/g.rs"), "ignored"),
        (s.0.join("ext/e.rs"), "outside"),
        (repo.join("src/later.rs"), "missing, then created untracked"),
    ] {
        fs::write(&file, "// v2\n").unwrap();
        let next = key(&repo, &spec, &probe).unwrap();
        assert_ne!(k, next, "{label}");
        k = next;
    }
}

#[test]
fn a_custom_target_specification_is_fingerprinted() {
    let s = scratch("target-spec");
    let (repo, mut probe) = setup(&s);
    fs::write(repo.join("x.json"), "{\"v\": 1}\n").unwrap();
    cargo_config_is(&repo, "[build]\ntarget = \"x.json\"\n");
    let fmt = fmt_gate();
    let spec = fmt.key_spec();
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::write(repo.join("x.json"), "{\"v\": 2}\n").unwrap();
    let k1 = key(&repo, &spec, &probe).unwrap();
    assert_ne!(k0, k1, "config target, tracked");
    let ext = s.0.join("y.json");
    fs::write(&ext, "{\"v\": 1}\n").unwrap();
    probe
        .vars
        .insert("CARGO_BUILD_TARGET".into(), ext.clone().into_os_string());
    let k2 = key(&repo, &spec, &probe).unwrap();
    fs::write(&ext, "{\"v\": 2}\n").unwrap();
    assert_ne!(
        k2,
        key(&repo, &spec, &probe).unwrap(),
        "env target, outside"
    );
    probe
        .vars
        .insert("CARGO_BUILD_TARGET".into(), "../later.json".into());
    let k3 = key(&repo, &spec, &probe).unwrap();
    fs::write(s.0.join("later.json"), "{}\n").unwrap();
    assert_ne!(
        k3,
        key(&repo, &spec, &probe).unwrap(),
        "env target, missing"
    );
}

#[test]
fn a_path_dependency_of_the_runner_crate_changes_every_key() {
    let s = scratch("runner-dep");
    let (repo, probe) = setup(&s);
    crate_dir(&s.0.join("rdep"), "");
    fs::write(
        probe.runner_dirs[0].join("Cargo.toml"),
        "[package]\nname = \"xtask\"\n\n[dependencies]\nrdep = { path = \"../rdep\" }\n",
    )
    .unwrap();
    let k0 = key(&repo, &NO_CARGO, &probe).unwrap();
    fs::write(s.0.join("rdep/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &NO_CARGO, &probe).unwrap());
}

#[test]
fn every_runner_directory_keys_a_narrowed_gate() {
    // A project runner built on the template as a library: both crates are
    // the runner, so a change to either re-runs every gate.
    let s = scratch("runner-dirs");
    let (repo, mut probe) = setup(&s);
    let lib = s.0.join("runner-lib");
    fs::create_dir_all(&lib).unwrap();
    fs::write(lib.join("gates.rs"), "// library gate code\n").unwrap();
    fs::write(lib.join("Cargo.toml"), "[package]\nname = \"xtask\"\n").unwrap();
    probe.runner_dirs.push(lib.clone());
    let k0 = key(&repo, &RS, &probe).unwrap();
    fs::write(lib.join("gates.rs"), "// changed\n").unwrap();
    let k1 = key(&repo, &RS, &probe).unwrap();
    assert_ne!(k0, k1, "second runner directory's source");
    fs::write(
        lib.join("Cargo.toml"),
        "[package]\nname = \"xtask\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    assert_ne!(k1, key(&repo, &RS, &probe).unwrap(), "its manifest");
}

#[test]
fn the_sysroot_rustc_changes_every_key() {
    let s = scratch("runner-rustc");
    let (repo, mut probe) = setup(&s);
    let sysroot = s.0.join("sysroot");
    fs::create_dir_all(sysroot.join("bin")).unwrap();
    write_exe(&sysroot.join("bin/rustc"), "#!/bin/sh\n");
    probe.sysroot = Some(sysroot.clone());
    let k0 = key(&repo, &NO_CARGO, &probe).unwrap();
    write_exe(&sysroot.join("bin/rustc"), "#!/bin/sh\n# updated\n");
    assert_ne!(k0, key(&repo, &NO_CARGO, &probe).unwrap());
}

#[test]
fn the_runner_build_environment_changes_a_non_cargo_key() {
    let s = scratch("runner-env");
    let (repo, mut probe) = setup(&s);
    let k0 = key(&repo, &NO_CARGO, &probe).unwrap();
    probe
        .vars
        .insert("CARGO_PROFILE_DEV_DEBUG".into(), "0".into());
    assert_ne!(k0, key(&repo, &NO_CARGO, &probe).unwrap());
}

#[test]
fn an_ancestor_cargo_config_changes_a_non_cargo_key() {
    let s = scratch("runner-ancestor-config");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(s.0.join(".cargo")).unwrap();
    fs::write(s.0.join(".cargo/config.toml"), "[build]\njobs = 1\n").unwrap();
    let k0 = key(&repo, &NO_CARGO, &probe).unwrap();
    fs::write(s.0.join(".cargo/config.toml"), "[build]\njobs = 2\n").unwrap();
    assert_ne!(k0, key(&repo, &NO_CARGO, &probe).unwrap());
}

#[test]
fn a_rustc_wrapper_changes_a_non_cargo_key() {
    let s = scratch("runner-wrapper");
    let (repo, mut probe) = setup(&s);
    let wrapper = s.0.join("wrap.sh");
    write_exe(&wrapper, "#!/bin/sh\nexec \"$@\"\n");
    probe
        .vars
        .insert("RUSTC_WRAPPER".into(), wrapper.clone().into_os_string());
    let k0 = key(&repo, &NO_CARGO, &probe).unwrap();
    write_exe(&wrapper, "#!/bin/sh\necho wrapped; exec \"$@\"\n");
    assert_ne!(k0, key(&repo, &NO_CARGO, &probe).unwrap());
}

#[test]
fn no_home_makes_a_non_cargo_key_an_error() {
    let s = scratch("runner-no-home");
    let (repo, mut probe) = setup(&s);
    probe.home = None;
    let err = key(&repo, &NO_CARGO, &probe).unwrap_err();
    assert!(err.contains("HOME is unset or empty"), "{err}");
}

/// duplication's own declaration, as the registry has it: narrowed inputs,
/// no cargo, served from the cache on main.
fn duplication_gate() -> xtask::Gate {
    xtask::registry()
        .into_iter()
        .find(|g| g.name == "duplication")
        .unwrap()
}

#[test]
fn the_root_manifest_content_changes_a_narrowed_non_cargo_key() {
    let s = scratch("runner-root-manifest");
    let (repo, probe) = setup(&s);
    manifest_is(&repo, "[workspace]\nmembers = []\n");
    let dup = duplication_gate();
    let k0 = key(&repo, &dup.key_spec(), &probe).unwrap();
    fs::write(
        repo.join("Cargo.toml"),
        "[workspace]\nmembers = []\n\n[profile.dev]\noverflow-checks = false\n",
    )
    .unwrap();
    assert_ne!(k0, key(&repo, &dup.key_spec(), &probe).unwrap());
}

#[test]
fn the_root_cargo_config_content_changes_a_narrowed_non_cargo_key() {
    let s = scratch("runner-root-config");
    let (repo, probe) = setup(&s);
    cargo_config_is(&repo, "[build]\njobs = 1\n");
    let dup = duplication_gate();
    let k0 = key(&repo, &dup.key_spec(), &probe).unwrap();
    fs::write(repo.join(".cargo/config.toml"), "[build]\njobs = 2\n").unwrap();
    assert_ne!(k0, key(&repo, &dup.key_spec(), &probe).unwrap());
}

#[test]
fn a_tracked_included_config_changes_a_narrowed_non_cargo_key() {
    let s = scratch("runner-tracked-include");
    let (repo, probe) = setup(&s);
    fs::create_dir_all(repo.join(".cargo")).unwrap();
    fs::write(repo.join(".cargo/shared.toml"), "[env]\nX = \"1\"\n").unwrap();
    cargo_config_is(&repo, "include = [\"shared.toml\"]\n");
    let dup = duplication_gate();
    let k0 = key(&repo, &dup.key_spec(), &probe).unwrap();
    fs::write(repo.join(".cargo/shared.toml"), "[env]\nX = \"2\"\n").unwrap();
    assert_ne!(k0, key(&repo, &dup.key_spec(), &probe).unwrap());
}

#[test]
fn the_declaration_changes_the_key() {
    let s = scratch("decl");
    let (repo, probe) = setup(&s);
    let with = |decl| KeySpec { decl, ..RS };
    let one = key(&repo, &with("kind=Kani memory=1"), &probe).unwrap();
    let two = key(&repo, &with("kind=Kani memory=2"), &probe).unwrap();
    assert_ne!(one, two);
    assert_eq!(
        key(&repo, &with(""), &probe).unwrap(),
        key(&repo, &RS, &probe).unwrap()
    );
}

/// A root package that is its own workspace member (`members = ["."]`), with
/// ignored files under `fuzz/corpus/` and `gen/`.
fn root_package(repo: &Path, not_inputs: &str) {
    fs::write(repo.join(".gitignore"), "out/\n/fuzz/corpus\n/gen\n").unwrap();
    fs::create_dir_all(repo.join("fuzz/corpus")).unwrap();
    fs::create_dir_all(repo.join("gen")).unwrap();
    fs::write(repo.join("fuzz/corpus/seed"), "v1").unwrap();
    fs::write(repo.join("gen/data"), "v1").unwrap();
    manifest_is(
        repo,
        &format!(
            "[package]\nname = \"a\"\n\n[workspace]\nmembers = [\".\"]\n\n\
             [workspace.metadata.disciplines]\n{not_inputs}"
        ),
    );
}

#[test]
fn a_root_package_fingerprints_every_ignored_file_by_default() {
    let s = scratch("root-package");
    let (repo, probe) = setup(&s);
    root_package(&repo, "");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("fuzz/corpus/seed"), "v2").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn not_inputs_drops_ignored_files_below_the_listed_directories() {
    let s = scratch("not-inputs");
    let (repo, probe) = setup(&s);
    root_package(&repo, "not_inputs = [\"fuzz/corpus\"]\n");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("fuzz/corpus/seed"), "v2").unwrap();
    fs::write(repo.join("fuzz/corpus/new"), "x").unwrap();
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap(), "excluded");
    fs::write(repo.join("gen/data"), "v2").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap(), "not excluded");
}

#[test]
fn not_inputs_lifts_the_ignored_file_limit_for_the_listed_directories() {
    let s = scratch("not-inputs-limit");
    let (repo, probe) = setup(&s);
    root_package(&repo, "not_inputs = [\"fuzz/corpus\"]\n");
    let corpus = repo.join("fuzz/corpus");
    for i in 0..=xtask::cache::outside::OUTSIDE_FILE_LIMIT {
        fs::write(corpus.join(i.to_string()), "").unwrap();
    }
    assert!(key(&repo, &TREE, &probe).is_ok());
    root_package(&repo, "");
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains("more than"), "{err}");
}

#[test]
fn changing_not_inputs_changes_every_key() {
    let s = scratch("not-inputs-keyed");
    let (repo, probe) = setup(&s);
    root_package(&repo, "not_inputs = [\"fuzz/corpus\"]\n");
    let (cargo0, plain0) = (
        key(&repo, &RS, &probe).unwrap(),
        key(&repo, &NO_CARGO, &probe).unwrap(),
    );
    root_package(&repo, "not_inputs = [\"fuzz/corpus\", \"gen\"]\n");
    assert_ne!(cargo0, key(&repo, &RS, &probe).unwrap(), "cargo gate");
    assert_ne!(plain0, key(&repo, &NO_CARGO, &probe).unwrap(), "other gate");
}

#[test]
fn declared_ignored_inputs_still_match_inside_not_inputs() {
    let s = scratch("not-inputs-declared");
    let (repo, probe) = setup(&s);
    root_package(&repo, "not_inputs = [\"fuzz/corpus\"]\n");
    let spec = KeySpec {
        ignored_inputs: &["fuzz/corpus/*"],
        ..TREE
    };
    let k0 = key(&repo, &spec, &probe).unwrap();
    fs::write(repo.join("fuzz/corpus/seed"), "v2").unwrap();
    assert_ne!(k0, key(&repo, &spec, &probe).unwrap());
}

#[test]
fn an_invalid_not_inputs_entry_makes_the_key_an_error() {
    let s = scratch("not-inputs-invalid");
    let (repo, probe) = setup(&s);
    for bad in ["\"../x\"", "\"/abs\"", "\"fuzz/*\"", "\".\"", "\"\""] {
        root_package(&repo, &format!("not_inputs = [{bad}]\n"));
        let err = key(&repo, &TREE, &probe).unwrap_err();
        assert!(err.contains("not_inputs"), "{bad}: {err}");
    }
}

#[test]
fn a_path_value_naming_a_directory_inside_not_inputs_is_still_fingerprinted() {
    let s = scratch("not-inputs-named");
    let (repo, probe) = setup(&s);
    root_package(
        &repo,
        "not_inputs = [\"gen\"]\n\n[dependencies]\nq = { path = \"gen/q\" }\n",
    );
    crate_dir(&repo.join("gen/q"), "");
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("gen/q/src/lib.rs"), "pub fn changed() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn a_nested_repository_makes_a_narrowed_key_an_error() {
    let s = scratch("nested-narrow");
    let (repo, probe) = setup(&s);
    let nested = repo.join("sub");
    fs::create_dir_all(nested.join("src")).unwrap();
    git(&nested, &["init", "-q", "-b", "main"]);
    fs::write(nested.join("src/lib.rs"), "pub fn s() {}\n").unwrap();
    // Untracked: listed as one `sub/` entry.
    let err = key(&repo, &RS, &probe).unwrap_err();
    assert!(err.contains("sub"), "{err}");
    assert!(err.contains("not a regular file"), "{err}");
    // Added as a gitlink, as a submodule is.
    git(&nested, &["add", "-A"]);
    git(&nested, &["commit", "-qm", "sub"]);
    git(&repo, &["add", "sub"]);
    let err = key(&repo, &RS, &probe).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
}

#[test]
fn an_ignored_file_in_a_root_package_changes_a_cargo_key() {
    let s = scratch("root-package-ignored");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\nsrc/generated.rs\n").unwrap();
    manifest_is(&repo, "[package]\nname = \"r\"\n");
    fs::write(repo.join("src/generated.rs"), "pub fn g() {}\n").unwrap();
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("src/generated.rs"), "pub fn h() {}\n").unwrap();
    assert_ne!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn an_ignored_file_beside_a_virtual_workspace_root_does_not() {
    let s = scratch("virtual-root-ignored");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\nsrc/generated.rs\n").unwrap();
    manifest_is(&repo, "[workspace]\nmembers = []\n");
    fs::write(repo.join("src/generated.rs"), "pub fn g() {}\n").unwrap();
    let k0 = key(&repo, &TREE, &probe).unwrap();
    fs::write(repo.join("src/generated.rs"), "pub fn h() {}\n").unwrap();
    assert_eq!(k0, key(&repo, &TREE, &probe).unwrap());
}

#[test]
fn too_many_ignored_files_under_a_root_package_name_not_inputs() {
    let s = scratch("root-package-limit");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\ncorpus/\n").unwrap();
    manifest_is(&repo, "[package]\nname = \"r\"\n");
    fs::create_dir_all(repo.join("corpus")).unwrap();
    for i in 0..=xtask::cache::outside::OUTSIDE_FILE_LIMIT {
        fs::write(repo.join(format!("corpus/{i}")), "").unwrap();
    }
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains("more than 20000 files"), "{err}");
    assert!(
        err.contains("[workspace.metadata.disciplines] not_inputs"),
        "{err}"
    );
}

#[test]
fn an_ignored_directory_symlink_under_a_root_package_names_not_inputs() {
    // A Python venv always holds `lib64 -> lib`.
    let s = scratch("root-package-venv");
    let (repo, probe) = setup(&s);
    fs::write(repo.join(".gitignore"), "out/\n.venv/\n").unwrap();
    fs::create_dir_all(repo.join(".venv/lib")).unwrap();
    std::os::unix::fs::symlink("lib", repo.join(".venv/lib64")).unwrap();
    manifest_is(&repo, "[package]\nname = \"r\"\n");
    let err = key(&repo, &TREE, &probe).unwrap_err();
    assert!(err.contains(".venv/lib64"), "{err}");
    assert!(
        err.contains("[workspace.metadata.disciplines] not_inputs"),
        "{err}"
    );
    manifest_is(
        &repo,
        "[package]\nname = \"r\"\n\n[workspace]\n\n[workspace.metadata.disciplines]\nnot_inputs = [\".venv\"]\n",
    );
    assert!(key(&repo, &TREE, &probe).is_ok());
}
