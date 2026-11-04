// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! The six path-entry modes: `ro:` `rw:` `ri:` `wi:` `rs:` `ws:`. An idmapped one (`ri:`, `wi:`)
//! needs the `user` namespace; the writable ones (`rw:`, `wi:`, `ws:`) cannot list `/proc`.
mod common;

use common::{errs, node, ok};
use qinit_frames::error::Code;

/// A worker whose program `/bin/a` is covered by `ro:/bin`, next to the entries under test.
fn worker(namespaces: &str, paths: &str) -> String {
    format!(
        r#"
        [worker.a]
        exec = ["/bin/a"]
        credentials = {{ uid = "svc" }}
        sandbox = {{ namespaces = [{namespaces}], paths = ["ro:/bin", {paths}] }}
    "#
    )
}

#[test]
fn the_six_modes_parse_and_sort_by_path() {
    let r = ok(&worker(
        r#""user""#,
        r#""rs:/a", "wi:/b", "ro:/c", "ws:/d", "ri:/e", "rw:/f""#,
    ));
    let m = &r.model;
    let c = &m.creds[node(m, "a").cred.expect("cred") as usize];
    assert_eq!(
        c.paths,
        [
            "rs:/a", "wi:/b", "ro:/bin", "ro:/c", "ws:/d", "ri:/e", "rw:/f"
        ]
    );
    // Listed out of order, the compiler sorts by path, whatever the mode.
    let r = ok(&worker(r#""user""#, r#""ro:/c", "wi:/b", "rs:/a""#));
    let m = &r.model;
    let c = &m.creds[node(m, "a").cred.expect("cred") as usize];
    assert_eq!(c.paths, ["rs:/a", "wi:/b", "ro:/bin", "ro:/c"]);
}

#[test]
fn an_idmapped_mode_needs_the_user_namespace() {
    for entry in ["ri:/a", "wi:/a"] {
        let es = errs(&worker(r#""pid""#, &format!("\"{entry}\"")));
        assert_eq!(es.len(), 1, "{es:?}");
        assert_eq!(
            (es[0].code, es[0].key.as_str()),
            (Code::BadValue, "worker.a.sandbox.paths")
        );
        assert!(es[0].detail.contains(entry), "{}", es[0].detail);
        ok(&worker(r#""user""#, &format!("\"{entry}\"")));
    }
}

#[test]
fn a_writable_proc_is_refused_in_every_writable_mode() {
    for entry in ["rw:/proc", "wi:/proc", "ws:/proc"] {
        let es = errs(&worker(r#""user""#, &format!("\"{entry}\"")));
        assert_eq!(es.len(), 1, "{entry}: {es:?}");
        assert_eq!(es[0].key, "worker.a.sandbox.paths", "{entry}");
    }
    for entry in ["ro:/proc", "ri:/proc", "rs:/proc"] {
        ok(&worker(r#""user""#, &format!("\"{entry}\"")));
    }
}

#[test]
fn an_unknown_mode_is_refused() {
    for entry in ["rx:/a", "ws/a", "wo:/a", "rr:/a", "ro/a", "RO:/a", "ro: /a"] {
        let es = errs(&worker(r#""user""#, &format!("\"{entry}\"")));
        assert_eq!(es.len(), 1, "{entry}: {es:?}");
        assert_eq!(
            (es[0].code, es[0].key.as_str()),
            (Code::BadValue, "worker.a.sandbox.paths"),
            "{entry}"
        );
    }
}
