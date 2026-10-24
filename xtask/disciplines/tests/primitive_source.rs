// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! The primitive layer's source rules: a safe public API and no foreign
//! code.
use xtask::layers::primitive::findings;

fn found(src: &str) -> Vec<String> {
    findings("src/lib.rs", src).unwrap()
}

#[test]
fn safe_code_and_private_unsafe_pass() {
    let src = "pub fn f() -> u8 { 1 }\npub(crate) unsafe fn g() {}\nunsafe fn h() {}\n\
               pub struct S;\nimpl S { pub(crate) unsafe fn m(&self) {} pub fn n(&self) {} }\n\
               // SAFETY: S holds no pointers.\nunsafe impl Send for S {}\n\
               unsafe trait Private {}\n";
    assert_eq!(found(src), Vec::<String>::new());
}

#[test]
fn a_public_unsafe_fn_is_refused_free_or_in_an_impl() {
    let src = "pub unsafe fn f() {}\npub struct S;\nimpl S {\n    pub unsafe fn m(&self) {}\n}\n";
    assert_eq!(
        found(src),
        [
            "src/lib.rs:1: `pub unsafe fn f`: a primitive's public API is safe (wrap it, or make it pub(crate))",
            "src/lib.rs:4: `pub unsafe fn m`: a primitive's public API is safe (wrap it, or make it pub(crate))",
        ]
    );
}

#[test]
fn a_public_unsafe_trait_is_refused() {
    assert_eq!(
        found("pub unsafe trait T {}\n"),
        ["src/lib.rs:1: `pub unsafe trait T`: a primitive's public API is safe"]
    );
}

#[test]
fn foreign_code_is_refused() {
    let src = "extern \"C\" {\n    fn abs(x: i32) -> i32;\n}\n#[link(name = \"m\")]\nunsafe extern \"C\" {}\n#[no_mangle]\npub extern \"C\" fn e() {}\n#[export_name = \"x\"]\npub fn x() {}\n";
    let got = found(src);
    assert_eq!(got.len(), 5, "{got:#?}");
    assert!(
        got[0].starts_with("src/lib.rs:1: `extern` block"),
        "{got:#?}"
    );
    assert!(
        got.iter().any(|f| f.starts_with("src/lib.rs:4: `#[link]`")),
        "{got:#?}"
    );
    assert!(
        got.iter()
            .any(|f| f.starts_with("src/lib.rs:6: `#[no_mangle]`")),
        "{got:#?}"
    );
    assert!(
        got.iter()
            .any(|f| f.starts_with("src/lib.rs:8: `#[export_name]`")),
        "{got:#?}"
    );
}

#[test]
fn unsafe_wrapped_attributes_are_caught() {
    let got = found("#[unsafe(no_mangle)]\npub extern \"C\" fn e() {}\n");
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(got[0].contains("`#[no_mangle]`"), "{got:#?}");
}

#[test]
fn extern_crate_is_not_a_foreign_block() {
    assert_eq!(found("extern crate alloc;\n"), Vec::<String>::new());
}

#[test]
fn banned_attributes_inside_cfg_attr_are_caught() {
    let src = "#[cfg_attr(not(test), no_mangle)]\npub extern \"C\" fn a() {}\n\
               #[cfg_attr(x, unsafe(no_mangle))]\npub extern \"C\" fn b() {}\n\
               #[cfg_attr(x, inline, export_name = \"y\")]\npub fn c() {}\n\
               #[cfg_attr(a, cfg_attr(b, link(name = \"m\")))]\nextern crate alloc;\n\
               #[cfg_attr(x, link_section = \".data\")]\npub static S: u8 = 0;\n";
    let got = found(src);
    assert_eq!(got.len(), 4, "{got:#?}");
    assert!(
        got[0].starts_with("src/lib.rs:1: `#[no_mangle]`"),
        "{got:#?}"
    );
    assert!(
        got[1].starts_with("src/lib.rs:3: `#[no_mangle]`"),
        "{got:#?}"
    );
    assert!(
        got[2].starts_with("src/lib.rs:5: `#[export_name]`"),
        "{got:#?}"
    );
    assert!(got[3].starts_with("src/lib.rs:7: `#[link]`"), "{got:#?}");
}

#[test]
fn unsafe_methods_of_a_public_trait_are_refused() {
    let src = "pub trait T {\n    unsafe fn raw(&self);\n    unsafe fn dflt(&self) {}\n    fn safe(&self);\n}\n\
               trait Private {\n    unsafe fn ok(&self);\n}\n";
    assert_eq!(
        found(src),
        [
            "src/lib.rs:2: `unsafe fn raw` in pub trait `T`: a primitive's public API is safe",
            "src/lib.rs:3: `unsafe fn dflt` in pub trait `T`: a primitive's public API is safe",
        ]
    );
}

fn tree(root: &std::path::Path, files: &[(&str, &str)]) {
    for (path, text) in files {
        let p = root.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
}

#[test]
fn crate_files_follow_the_module_tree() {
    let root = std::env::temp_dir().join(format!("xtask-modtree-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(
        &root,
        &[
            (
                "lib.rs",
                "mod a;\n#[path = \"other/b_impl.rs\"]\nmod b;\nmod inline {\n    mod c;\n}\nmod d;\n",
            ),
            ("a.rs", "mod nested;\n"),
            ("a/nested.rs", ""),
            ("other/b_impl.rs", ""),
            ("inline/c.rs", ""),
            ("d/mod.rs", "mod e;\n"),
            ("d/e.rs", ""),
            ("tests/t.rs", "pub unsafe fn not_in_the_crate() {}\n"),
            ("target/debug/build/x.rs", "pub unsafe fn generated() {}\n"),
        ],
    );
    let got = xtask::layers::primitive::crate_sources(&root.join("lib.rs"))
        .unwrap()
        .files;
    let _ = std::fs::remove_dir_all(&root);
    let names: Vec<String> = got
        .iter()
        .map(|p| p.strip_prefix(&root).unwrap().display().to_string())
        .collect();
    assert_eq!(
        names,
        // Path order: by component, so `a/nested.rs` before `a.rs`.
        [
            "a/nested.rs",
            "a.rs",
            "d/e.rs",
            "d/mod.rs",
            "inline/c.rs",
            "lib.rs",
            "other/b_impl.rs"
        ]
    );
}

#[test]
fn ignored_module_files_are_named() {
    let root = std::env::temp_dir().join(format!("xtask-modign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(
        &root,
        &[
            ("src/lib.rs", "mod gen;\n"),
            ("src/gen.rs", ""),
            (".gitignore", "src/gen.rs\n"),
        ],
    );
    let ok = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&root)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let files = [root.join("src/lib.rs"), root.join("src/gen.rs")];
    let (got, outside) = xtask::layers::primitive::ignored(&root, &files).unwrap();
    assert_eq!(outside, Vec::<std::path::PathBuf>::new());
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(got, [root.join("src/gen.rs")]);
}

#[test]
fn macros_that_would_generate_banned_items_are_refused() {
    let src = "macro_rules! raw {\n    ($n:ident) => { pub unsafe fn $n() {} };\n}\n\
               macro_rules! ffi {\n    () => { extern \"C\" { fn abs(x: i32) -> i32; } };\n}\n\
               macro_rules! export {\n    () => { #[unsafe(no_mangle)] pub extern \"C\" fn e() {} };\n}\n\
               macro_rules! fine {\n    () => { pub fn safe() {} unsafe fn private() {} };\n}\n\
               some_crate::generate! { pub unsafe trait T {} }\n\
               println!(\"pub unsafe fn in a string\");\n";
    let got = found(src);
    assert_eq!(got.len(), 4, "{got:#?}");
    assert!(
        got[0].starts_with("src/lib.rs:1: macro `raw` can generate `pub unsafe fn`"),
        "{got:#?}"
    );
    assert!(
        got[1].starts_with("src/lib.rs:4: macro `ffi` can generate an `extern` block"),
        "{got:#?}"
    );
    assert!(
        got[2].starts_with("src/lib.rs:7: macro `export` can generate `#[no_mangle]`"),
        "{got:#?}"
    );
    assert!(
        got[3].starts_with(
            "src/lib.rs:13: macro `some_crate::generate` can generate `pub unsafe trait`"
        ),
        "{got:#?}"
    );
}

#[test]
fn every_unsafe_fn_spelling_in_a_macro_is_refused() {
    for body in [
        "pub unsafe extern \"C\" fn a() {}",
        "pub const unsafe fn b() {}",
        "pub async unsafe fn c() {}",
        "pub unsafe fn d() {}",
    ] {
        let src = format!("macro_rules! m {{ () => {{ {body} }}; }}\n");
        let got = found(&src);
        assert_eq!(got.len(), 1, "{body}: {got:#?}");
        assert!(
            got[0].contains("can generate `pub unsafe fn`"),
            "{body}: {got:#?}"
        );
    }
    let fine = "macro_rules! m { () => { pub(crate) unsafe fn x() {} pub const fn y() {} }; }\n";
    assert_eq!(found(fine), Vec::<String>::new());
}

#[test]
fn macro_tokens_respect_literals_and_comments() {
    let missed = "macro_rules! m { () => { const C: char = '\"'; pub unsafe fn x() {} }; }\n";
    assert_eq!(found(missed).len(), 1, "{:#?}", found(missed));
    let quiet = "macro_rules! m { () => {\n    // pub unsafe fn in a comment\n    const S: &str = r#\"pub unsafe fn \"in\" a raw string\"#;\n}; }\n";
    assert_eq!(found(quiet), Vec::<String>::new());
}

#[test]
fn cfg_attr_inside_a_macro_is_caught() {
    let got = found(
        "macro_rules! m { () => { #[cfg_attr(not(test), no_mangle)] pub extern \"C\" fn e() {} }; }\n",
    );
    assert_eq!(got.len(), 1, "{got:#?}");
    assert!(got[0].contains("`#[no_mangle]`"), "{got:#?}");
}

#[test]
fn includes_and_path_forms_reach_their_files() {
    let root = std::env::temp_dir().join(format!("xtask-include-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(
        &root,
        &[
            (
                "lib.rs",
                "include!(\"ffi.rs\");\n#[cfg_attr(unix, path = \"q.rs\")]\nmod p;\n#[path = r\"z.rs\"]\nmod z;\n",
            ),
            ("ffi.rs", "extern \"C\" { fn abs(x: i32) -> i32; }\n"),
            ("q.rs", ""),
            ("z.rs", ""),
        ],
    );
    let s = xtask::layers::primitive::crate_sources(&root.join("lib.rs")).unwrap();
    let names: Vec<String> = s
        .files
        .iter()
        .map(|p| p.strip_prefix(&root).unwrap().display().to_string())
        .collect();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(names, ["ffi.rs", "lib.rs", "q.rs", "z.rs"]);
    assert!(s.problems.is_empty(), "{:?}", s.problems);
}

#[test]
fn unreachable_sources_are_problems() {
    let root = std::env::temp_dir().join(format!("xtask-unreach-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(
        &root,
        &[(
            "lib.rs",
            "mod gone;\ninclude!(concat!(env!(\"OUT_DIR\"), \"/gen.rs\"));\n#[path = \"../../a/b/c.rs\"]\nmod cyc;\n",
        )],
    );
    let s = xtask::layers::primitive::crate_sources(&root.join("lib.rs")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    let msgs: Vec<String> = s
        .problems
        .iter()
        .map(|p| format!("{}: {}", p.line, p.message))
        .collect();
    assert_eq!(msgs.len(), 3, "{msgs:#?}");
    assert!(
        msgs[0].starts_with("1: module `gone` has no file"),
        "{msgs:#?}"
    );
    assert!(
        msgs[1].starts_with("2: `include!` of a path that is not a string literal"),
        "{msgs:#?}"
    );
    assert!(
        msgs[2].starts_with("4: module `cyc` has no file"),
        "{msgs:#?}"
    );
}

#[test]
fn sources_outside_the_repository_are_named_not_errors() {
    let base = std::env::temp_dir().join(format!("xtask-outside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    tree(&base, &[("repo/src/lib.rs", ""), ("elsewhere/x.rs", "")]);
    let repo = base.join("repo");
    let ok = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let files = [repo.join("src/lib.rs"), base.join("elsewhere/x.rs")];
    let got = xtask::layers::primitive::ignored(&repo, &files);
    let _ = std::fs::remove_dir_all(&base);
    let (ignored, outside) = got.unwrap();
    assert_eq!(ignored, Vec::<std::path::PathBuf>::new());
    assert_eq!(outside, [base.join("elsewhere/x.rs")]);
}

#[test]
fn modules_declared_inside_a_macro_are_followed() {
    let root = std::env::temp_dir().join(format!("xtask-macromod-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(
        &root,
        &[
            (
                "lib.rs",
                "cfg_if::cfg_if! {\n    if #[cfg(unix)] {\n        mod imp;\n    } else {\n        mod other;\n    }\n}\n",
            ),
            ("imp.rs", "pub unsafe fn danger() {}\n"),
            ("other/mod.rs", ""),
        ],
    );
    let s = xtask::layers::primitive::crate_sources(&root.join("lib.rs")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    let names: Vec<String> = s
        .files
        .iter()
        .map(|p| p.strip_prefix(&root).unwrap().display().to_string())
        .collect();
    assert_eq!(names, ["imp.rs", "lib.rs", "other/mod.rs"]);
    assert_eq!(s.problems, Vec::new());
}

#[test]
fn modules_a_macro_cannot_place_are_problems() {
    let root = std::env::temp_dir().join(format!("xtask-macromod-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(
        &root,
        &[(
            "lib.rs",
            "macro_rules! m {\n    () => { mod hidden; };\n}\nsome_macro! {\n    #[path = \"x.rs\"]\n    mod pathed;\n}\nsome_macro! { mod gone; }\n",
        )],
    );
    let s = xtask::layers::primitive::crate_sources(&root.join("lib.rs")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    let msgs: Vec<String> = s
        .problems
        .iter()
        .map(|p| format!("{}: {}", p.line, p.message))
        .collect();
    assert_eq!(
        msgs,
        [
            "1: module `hidden` is declared inside a macro definition: the source check cannot see it; declare it outside the macro",
            "4: module `pathed` is declared inside a macro with a `#[path]`: the source check cannot see it; declare it outside the macro",
            &format!(
                "8: module `gone` has no file (looked for {0}/gone.rs, {0}/gone/mod.rs): the source check cannot see it",
                root.display()
            ),
        ]
    );
}

#[test]
fn an_unreadable_source_is_a_problem() {
    let root = std::env::temp_dir().join(format!("xtask-unreadable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(&root, &[("lib.rs", "mod bad;\n")]);
    std::fs::write(root.join("bad.rs"), [0xff, 0xfe]).unwrap();
    let s = xtask::layers::primitive::crate_sources(&root.join("lib.rs")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(s.files, [root.join("lib.rs")]);
    assert_eq!(s.problems.len(), 1, "{:?}", s.problems);
    assert_eq!(s.problems[0].file, root.join("bad.rs"));
    assert_eq!(s.problems[0].line, 1);
    assert!(
        s.problems[0].message.starts_with("cannot read it (")
            && s.problems[0]
                .message
                .ends_with("): the source check cannot see it"),
        "{:?}",
        s.problems
    );
}

#[test]
fn ignored_survives_output_larger_than_a_pipe() {
    let base = std::env::temp_dir().join(format!("xtask-ignored-big-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(base.join("gen")).unwrap();
    std::fs::write(base.join(".gitignore"), "gen/\n").unwrap();
    let ok = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&base)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let long = "x".repeat(150);
    let files: Vec<std::path::PathBuf> = (0..2000)
        .map(|i| {
            let f = base.join("gen").join(format!("{long}{i}.rs"));
            std::fs::write(&f, "").unwrap();
            f
        })
        .collect();
    let (tx, rx) = std::sync::mpsc::channel();
    let b = base.clone();
    std::thread::spawn(move || {
        tx.send(xtask::layers::primitive::ignored(&b, &files))
            .unwrap();
    });
    // In slices: a pause of the gate step costs one, not the deadline.
    let got = xtask::watch::Budget::new(std::time::Duration::from_secs(20)).recv(&rx);
    let _ = std::fs::remove_dir_all(&base);
    let (ignored, outside) = got.expect("ignored() deadlocked").unwrap();
    assert_eq!(ignored.len(), 2000);
    assert_eq!(outside, Vec::<std::path::PathBuf>::new());
}

#[test]
fn modules_in_token_producing_macros_are_not_declarations() {
    let root = std::env::temp_dir().join(format!("xtask-quote-mod-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    tree(
        &root,
        &[(
            "lib.rs",
            "fn f() {\n    let _ = quote::quote! { mod generated; };\n    let _ = quote_spanned! { span => mod other; };\n}\n",
        )],
    );
    let s = xtask::layers::primitive::crate_sources(&root.join("lib.rs")).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(s.files, [root.join("lib.rs")]);
    assert_eq!(s.problems, Vec::new());
}
