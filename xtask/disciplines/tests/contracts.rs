// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The spine interface: contracted bodies erased, everything else kept.
use xtask::cache::contracts::interface_text;

const BASE: &str = "\
pub struct S { pub a: u8 }
#[cfg_attr(kani, kani::requires(x < 100))]
#[cfg_attr(kani, kani::ensures(|r: &u32| *r == x + 1))]
pub fn inc(x: u32) -> u32 { x + 1 }
pub fn other(x: u32) -> u32 { x * 2 }
impl S {
    #[kani::ensures(|r: &u8| *r == self.a)]
    pub fn get(&self) -> u8 { self.a }
}
";

fn text(src: &str) -> String {
    interface_text("crates/s/src/lib.rs", src).unwrap()
}

#[test]
fn a_contracted_body_edit_keeps_the_interface() {
    let edited = BASE.replace("{ x + 1 }", "{ let y = x; y + 1 }");
    assert_eq!(text(BASE), text(&edited));
    let method = BASE.replace("{ self.a }", "{ let a = self.a; a }");
    assert_eq!(text(BASE), text(&method));
}

#[test]
fn anything_else_changes_it() {
    for (what, from, to) in [
        ("contract", "x < 100", "x < 50"),
        (
            "signature",
            "pub fn inc(x: u32) -> u32",
            "pub fn inc(x: u64) -> u32",
        ),
        ("uncontracted body", "{ x * 2 }", "{ x * 3 }"),
        ("type", "pub a: u8", "pub a: u16"),
    ] {
        assert_ne!(text(BASE), text(&BASE.replace(from, to)), "{what}");
    }
}

#[test]
fn the_path_is_part_of_the_text() {
    assert!(text("fn f() {}").starts_with("// crates/s/src/lib.rs\n"));
    assert_ne!(
        interface_text("a.rs", "fn f() {}").unwrap(),
        interface_text("b.rs", "fn f() {}").unwrap()
    );
}

#[test]
fn erased_bodies_read_as_empty_blocks() {
    let t = text(BASE);
    assert!(t.contains("pub fn inc(x: u32) -> u32 {}"), "{t}");
    assert!(t.contains("pub fn other(x: u32) -> u32 { x * 2 }"), "{t}");
}

#[test]
fn only_real_contract_attributes_count() {
    let src = "#[doc = \"see kani::ensures\"]\npub fn f(x: u8) -> u8 { x }\n\
               #[cfg_attr(kani, inline)]\n#[allow(dead_code, reason = \"kani::requires\")]\npub fn g() { body() }\n\
               #[cfg_attr(all(kani, test), kani::requires(true))]\npub fn h() { body() }\n";
    let t = text(src);
    assert!(t.contains("pub fn f(x: u8) -> u8 { x }"), "{t}");
    assert!(t.contains("pub fn g() { body() }"), "{t}");
    assert!(t.contains("pub fn h() {}"), "{t}");
}

#[test]
fn spine_sources_follow_git_not_the_disk() {
    use std::fs;
    let root = std::env::temp_dir().join(format!("xtask-spine-src-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("crates/s/src/gen")).unwrap();
    let git = |args: &[&str]| {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(&root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "git {args:?}");
    };
    git(&["init", "-q"]);
    fs::write(root.join(".gitignore"), "crates/s/src/gen/\n").unwrap();
    fs::write(root.join("crates/s/src/lib.rs"), "pub fn a() {}").unwrap();
    fs::write(root.join("crates/s/src/new.rs"), "pub fn b() {}").unwrap();
    fs::write(root.join("crates/s/src/gen/out.rs"), "pub fn c() {}").unwrap();
    fs::write(root.join("real.rs"), "pub fn d() {}").unwrap();
    std::os::unix::fs::symlink("../../../real.rs", root.join("crates/s/src/linked.rs")).unwrap();
    git(&["add", "crates/s/src/lib.rs"]);
    let got = xtask::cache::contracts::spine_sources(&root, "crates/s").unwrap();
    let _ = fs::remove_dir_all(&root);
    let names: Vec<String> = got
        .iter()
        .map(|p| p.strip_prefix(&root).unwrap().display().to_string())
        .collect();
    assert_eq!(
        names,
        [
            "crates/s/src/lib.rs",
            "crates/s/src/linked.rs",
            "crates/s/src/new.rs"
        ]
    );
}
