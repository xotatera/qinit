// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

use xtask::duplication::extract::{Function, functions};

fn fns(src: &str) -> Vec<Function> {
    functions("src/lib.rs", src).expect("parse")
}

fn by_name<'a>(fns: &'a [Function], suffix: &str) -> &'a Function {
    fns.iter()
        .find(|f| f.key.ends_with(suffix))
        .unwrap_or_else(|| {
            panic!(
                "no {suffix} in {:?}",
                fns.iter().map(|f| &f.key).collect::<Vec<_>>()
            )
        })
}

#[test]
fn local_names_do_not_matter() {
    let f = fns("fn total(items: &[u32]) -> u32 { let mut sum = 0; for x in items { sum += x * 2; } sum }
                 fn twice(values: &[u32]) -> u32 { let mut acc = 0; for v in values { acc += v * 2; } acc }");
    assert_eq!(by_name(&f, "::total").strict, by_name(&f, "::twice").strict);
}

#[test]
fn field_names_matter_in_strict_but_not_in_loose() {
    let f = fns(
        "impl S { fn width(&self) -> u32 { self.w + 1 } fn height(&self) -> u32 { self.h + 1 } }",
    );
    let (w, h) = (by_name(&f, "S::width"), by_name(&f, "S::height"));
    assert_ne!(w.strict, h.strict);
    assert_eq!(w.loose, h.loose);
}

#[test]
fn string_literals_do_not_matter() {
    let f = fns(
        r##"fn a(c: &C, t: i64) -> u64 { c.execute("DELETE FROM a WHERE ts < ?1", t) }
                   fn b(c: &C, t: i64) -> u64 { c.execute(r#"DELETE FROM b WHERE ts < ?1"#, t) }"##,
    );
    assert_eq!(by_name(&f, "::a").strict, by_name(&f, "::b").strict);
}

#[test]
fn comments_do_not_matter() {
    let f = fns("fn a(x: u8) -> u8 { // first\n x + 1 }\nfn b(x: u8) -> u8 { /* second */ x + 1 }");
    assert_eq!(by_name(&f, "::a").strict, by_name(&f, "::b").strict);
}

#[test]
fn numbers_matter_in_strict_but_not_in_loose() {
    let f = fns("fn soft() -> Cfg { Cfg { gain: 0.5, ..Cfg::default() } }
                 fn hard() -> Cfg { Cfg { gain: 0.9, ..Cfg::default() } }");
    let (s, h) = (by_name(&f, "::soft"), by_name(&f, "::hard"));
    assert_ne!(s.strict, h.strict);
    assert_eq!(s.loose, h.loose);
}

#[test]
fn enum_variants_in_patterns_are_not_renamed() {
    let f = fns("fn r(c: Color) -> u8 { match c { Red => 1, _ => 0 } }
                 fn b(c: Color) -> u8 { match c { Blue => 1, _ => 0 } }");
    assert_ne!(by_name(&f, "::r").strict, by_name(&f, "::b").strict);
}

#[test]
fn calls_in_match_guards_are_not_renamed() {
    let f = fns(
        "fn a(x: u8) -> u8 { match x { y if is_ok(y) => 1, _ => 0 } }
                 fn b(x: u8) -> u8 { match x { y if is_err(y) => 1, _ => 0 } }",
    );
    assert_ne!(by_name(&f, "::a").strict, by_name(&f, "::b").strict);
}

#[test]
fn keys_carry_scope() {
    let f = fns("mod m { fn g() {} }
                 struct Foo;
                 impl Foo { fn a(&self) {} }
                 impl std::fmt::Display for Foo { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { Ok(()) } }
                 trait T { fn d(&self) { } }");
    let keys: Vec<&str> = f.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "src/lib.rs::m::g",
            "src/lib.rs::Foo::a",
            "src/lib.rs::<Foo as std::fmt::Display>::fmt",
            "src/lib.rs::T::d"
        ]
    );
}

#[test]
fn repeated_names_get_distinct_keys() {
    let f = fns("#[cfg(unix)] fn f() -> u8 { 1 }\n#[cfg(windows)] fn f() -> u8 { 1 }");
    let keys: Vec<&str> = f.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys, ["src/lib.rs::f", "src/lib.rs::f~2"]);
}

#[test]
fn test_code_is_marked() {
    let f = fns("#[test] fn t() { assert!(true); }
                 #[tokio::test] async fn ta() {}
                 #[cfg(test)] mod tests { fn helper() {} }
                 #[cfg(not(test))] fn real() {}
                 fn plain() {}");
    for (suffix, is_test) in [
        ("::t", true),
        ("::ta", true),
        ("tests::helper", true),
        ("::real", false),
        ("::plain", false),
    ] {
        assert_eq!(by_name(&f, suffix).is_test, is_test, "{suffix}");
    }
    assert!(functions("tests/it.rs", "fn x() {}").unwrap()[0].is_test);
}

#[test]
fn syntax_errors_do_not_panic_and_keep_readable_functions() {
    let f = fns("fn ok() -> u8 { 1 }\nfn broken( { let = ; }\nfn also_ok() -> u8 { 2 }");
    assert!(f.iter().any(|f| f.key.ends_with("::ok")));
    assert!(f.iter().any(|f| f.key.ends_with("::also_ok")));
}

#[test]
fn line_is_the_fn_line() {
    let f = fns("\n\nfn third() {}");
    assert_eq!(f[0].line, 3);
}

fn strict_pair(a: &str, b: &str, name_a: &str, name_b: &str) -> (Vec<String>, Vec<String>) {
    let src = format!("{a}\n{b}");
    let f = fns(&src);
    (
        by_name(&f, name_a).strict.clone(),
        by_name(&f, name_b).strict.clone(),
    )
}

#[test]
fn macro_fields_and_methods_are_not_renamed() {
    let (a, b) = strict_pair(
        "fn a(p: &P, w: u32) { assert_eq!(p.w, w); }",
        "fn b(p: &P, h: u32) { assert_eq!(p.h, h); }",
        "::a",
        "::b",
    );
    assert_ne!(a, b);
    let (a, b) = strict_pair(
        "fn a(v: &V, len: usize) { assert_eq!(v.len(), len); }",
        "fn b(v: &V, cap: usize) { assert_eq!(v.cap(), cap); }",
        "::a",
        "::b",
    );
    assert_ne!(a, b);
}

#[test]
fn shorthand_struct_init_keeps_field_names() {
    let (a, b) = strict_pair(
        "impl P { fn new(x: u32, y: u32) -> Self { Self { x, y } } }",
        "impl Q { fn mk(w: u32, h: u32) -> Self { Self { w, h } } }",
        "::new",
        "::mk",
    );
    assert_ne!(a, b);
    let (a, b) = strict_pair(
        "fn a(w: u32) -> T { T { w, ..T::default() } }",
        "fn b(h: u32) -> T { T { h, ..T::default() } }",
        "::a",
        "::b",
    );
    assert_ne!(a, b);
}

#[test]
fn path_segments_are_not_renamed_to_a_local() {
    let (a, b) = strict_pair(
        "fn a(x: u32, max: u32) -> u32 { std::cmp::max(x, max) }",
        "fn b(x: u32, min: u32) -> u32 { std::cmp::min(x, min) }",
        "::a",
        "::b",
    );
    assert_ne!(a, b);
}

#[test]
fn closure_param_types_are_not_locals() {
    let (a, b) = strict_pair(
        "fn a() -> usize { let f = |x: [u8; io]| x; io }",
        "fn b() -> usize { let f = |x: [u8; fs]| x; fs }",
        "::a",
        "::b",
    );
    assert_ne!(a, b);
}

#[test]
fn match_arm_bindings_are_renamed() {
    let (a, b) = strict_pair(
        "fn a(o: Option<u8>) -> u8 { match o { Some(a) => a + 1, None => 0 } }",
        "fn b(o: Option<u8>) -> u8 { match o { Some(b) => b + 1, None => 0 } }",
        "::a",
        "::b",
    );
    assert_eq!(a, b);
}

#[test]
fn if_let_and_while_let_bindings_are_renamed() {
    let (a, b) = strict_pair(
        "fn a(o: Option<u8>) -> u8 { if let Some(p) = o { return p; } while let Some(q) = o { return q; } 0 }",
        "fn b(o: Option<u8>) -> u8 { if let Some(r) = o { return r; } while let Some(s) = o { return s; } 0 }",
        "::a",
        "::b",
    );
    assert_eq!(a, b);
}

#[test]
fn closure_params_are_renamed() {
    let (a, b) = strict_pair(
        "fn a(v: &[u8]) -> Vec<u8> { v.iter().map(|x| x + 1).collect() }",
        "fn b(v: &[u8]) -> Vec<u8> { v.iter().map(|y| y + 1).collect() }",
        "::a",
        "::b",
    );
    assert_eq!(a, b);
}

#[test]
fn loose_renames_free_functions_types_and_chars() {
    for (x, y) in [
        (
            "fn a() -> u8 { helper_one(1) }",
            "fn b() -> u8 { helper_two(1) }",
        ),
        (
            "fn a() -> u8 { let v: Alpha = make(); v.n }",
            "fn b() -> u8 { let v: Beta = make(); v.n }",
        ),
        ("fn a() -> char { 'x' }", "fn b() -> char { 'y' }"),
    ] {
        let f = fns(&format!("{x}\n{y}"));
        let (a, b) = (by_name(&f, "::a"), by_name(&f, "::b"));
        assert_ne!(a.strict, b.strict, "{x}");
        assert_eq!(a.loose, b.loose, "{x}");
    }
}

#[test]
fn tests_file_stem_and_inner_cfg_test_mark_everything() {
    assert!(functions("src/foo/tests.rs", "fn x() {}").unwrap()[0].is_test);
    let f = fns("#![cfg(test)]\nfn x() {}\nfn y() {}");
    assert!(f.iter().all(|f| f.is_test));
}

#[test]
fn macro_names_are_never_renamed_as_locals() {
    let (a, b) = strict_pair(
        "fn a() -> Vec<u8> { let vec = 1; vec![vec] }",
        "fn b() -> Vec<u8> { let x = 1; vec![x] }",
        "::a",
        "::b",
    );
    assert_eq!(a, b);
}

#[test]
fn loop_labels_are_not_identifiers() {
    // A label is its own node kind, so a local of the same name is unaffected.
    let (a, b) = strict_pair(
        "fn a() { let outer = 1; 'outer: loop { break 'outer; } let _ = outer; }",
        "fn b() { let x = 1; 'outer: loop { break 'outer; } let _ = x; }",
        "::a",
        "::b",
    );
    assert_eq!(a, b);
}

fn is_test_with(attr: &str) -> bool {
    let f = fns(&format!("{attr}\nfn a() {{}}"));
    by_name(&f, "::a").is_test
}

#[test]
fn test_attributes_match_exactly() {
    for attr in [
        "#[test]",
        "#[ tokio::test ]",
        "#[tokio :: test]",
        "#[tokio::test(flavor = \"multi_thread\")]",
        "#[sqlx::test(migrations = \"x\")]",
        "#[test(arg)]",
        "#[rstest]",
        "#[cfg(test)]",
        "#[cfg(all(test, feature = \"x\"))]",
        "#[cfg(all(unix, any(test, test)))]",
        "#[cfg(all(unix, not(windows), test))]",
    ] {
        assert!(is_test_with(attr), "{attr} should be a test");
    }
    for attr in [
        "#[contest]",
        "#[latest]",
        "#[cfg(any(test, miri))]",
        "#[cfg(any(test, unix))]",
        "#[cfg(not(test))]",
        "#[cfg(not(any(test, miri)))]",
        "#[cfg(feature = \"test\")]",
        "#[cfg(testing)]",
        "#[cfg_attr(test, inline)]",
        "#[inline]",
    ] {
        assert!(!is_test_with(attr), "{attr} should not be a test");
    }
}

#[test]
fn macro_names_inside_macro_arguments_are_kept() {
    let (a, b) = strict_pair(
        "fn a() { let vec = 1; f!(vec![vec]); }",
        "fn b() { let format = 1; f!(format![format]); }",
        "::a",
        "::b",
    );
    assert_ne!(a, b);
}

#[test]
fn lifetimes_are_not_renamed_as_locals() {
    let (a, b) = strict_pair(
        "fn a() { let a = 1; let r: &'a u8 = &a; }",
        "fn b() { let b = 1; let r: &'b u8 = &b; }",
        "::a",
        "::b",
    );
    assert_ne!(a, b);
}

#[test]
fn inner_cfg_test_marks_the_file() {
    let f = functions("src/lib.rs", "#![cfg(test)]\nfn a() {}").unwrap();
    assert!(f[0].is_test);
    let f = functions("src/lib.rs", "#![cfg(not(test))]\nfn a() {}").unwrap();
    assert!(!f[0].is_test);
}
