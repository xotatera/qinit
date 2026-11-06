// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! Template and instance expansion.
use qinit_db::Kind;
use qinit_frames::error::{Code, Error};
use qinit_frames::expand::{Expanded, expand};
use qinit_frames::layers::Merged;
use qinit_frames::provenance::{FrameKey, Origin};
use qinit_frames::schema::{Frame, Output, Ready};
use std::collections::BTreeMap;

fn merged(src: &str) -> Merged {
    Merged {
        table: src.parse::<toml::Table>().expect("test toml"),
        provenance: BTreeMap::new(),
    }
}

fn ok(src: &str) -> Expanded {
    expand(&merged(src)).expect("expands")
}

fn errs(src: &str) -> Vec<Error> {
    expand(&merged(src)).expect_err("refused")
}

fn frame<'a>(e: &'a Expanded, name: &str) -> &'a Frame {
    &e.frames
        .iter()
        .find(|(n, _, _)| n == name)
        .unwrap_or_else(|| panic!("no frame {name}"))
        .2
}

fn targets(f: &Frame) -> Vec<String> {
    f.deps
        .iter()
        .flatten()
        .flat_map(|g| g.edges.iter().filter_map(|e| e.to.clone()))
        .collect()
}

#[test]
fn a_template_supplies_defaults_a_frame_overrides() {
    let e = ok(r#"
        [template.daemon]
        exec = ["/bin/default"]
        ready = "exit"
        restart = { policy = "always" }
        [worker.sshd]
credentials = { uid = "svc" }
        template = "daemon"
        exec = ["/usr/bin/sshd", "-D"]
    "#);
    let f = frame(&e, "sshd");
    assert_eq!(
        f.exec.as_deref(),
        Some(&["/usr/bin/sshd".into(), "-D".into()][..])
    );
    assert!(matches!(f.ready, Some(Ready::Kind(ref k)) if k == "exit"));
    assert_eq!(
        f.restart.as_ref().map(|r| r.policy.as_str()),
        Some("always")
    );
    assert!(e.frames.iter().all(|(n, _, _)| n != "daemon"));
}

#[test]
fn template_deps_come_first_then_frame_deps() {
    let e = ok(r#"
        [template.daemon]
        deps = [{ group = "require_all", edges = [{ to = "a" }] }]
        [worker.x]
credentials = { uid = "svc" }
        template = "daemon"
        exec = ["/x"]
        deps = [{ group = "require_all", edges = [{ to = "b" }] }]
        [brood.a]
        [brood.b]
    "#);
    assert_eq!(targets(frame(&e, "x")), ["a", "b"]);
}

#[test]
fn a_template_naming_a_template_is_refused() {
    let es = errs(
        r#"
        [template.base]
        exec = ["/x"]
        [template.daemon]
        template = "base"
        [worker.x]
credentials = { uid = "svc" }
        template = "daemon"
    "#,
    );
    assert!(es.iter().any(|e| e.code == Code::Template), "{es:?}");
}

#[test]
fn a_missing_template_is_refused() {
    let es =
        errs("[worker.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\ntemplate = \"nope\"\n");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Template);
    assert_eq!(es[0].key, "worker.x.template");
}

#[test]
fn instances_expand_with_percent_i_substituted() {
    let e = ok(r#"
        [worker.getty]
        exec = ["/sbin/agetty", "%i"]
        instances = ["tty1", "tty2"]
        ready = { path = "/run/getty-%i" }
        output = "/var/log/getty-%i"
        credentials = { uid = "getty-%i" }
    "#);
    let names: Vec<_> = e.frames.iter().map(|(n, _, _)| n.as_str()).collect();
    assert_eq!(names, ["getty@tty1", "getty@tty2"]);
    let f = frame(&e, "getty@tty2");
    assert_eq!(
        f.exec.as_deref(),
        Some(&["/sbin/agetty".into(), "tty2".into()][..])
    );
    assert!(matches!(f.ready, Some(Ready::Path { ref path }) if path == "/run/getty-tty2"));
    assert!(matches!(f.output, Some(Output::Path(ref p)) if p == "/var/log/getty-tty2"));
    assert_eq!(
        f.credentials.as_ref().map(|c| c.uid.as_str()),
        Some("getty-tty2")
    );
    assert!(f.instances.is_none());
}

#[test]
fn instance_names_that_break_the_name_rules_are_refused() {
    let long = "a".repeat(96);
    for bad in ["", "a/b", "a\\u0000b", "../x", "a@b", long.as_str()] {
        let src = format!(
            "[worker.g]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/x\"]\ninstances = [\"{bad}\"]\n"
        );
        let es = errs(&src);
        assert!(es.iter().all(|e| e.code == Code::BadName), "{bad}: {es:?}");
        assert!(!es.is_empty(), "{bad}");
    }
    let es = errs("[worker.\"a@b\"]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n");
    assert_eq!(es[0].code, Code::BadName);
    let es = errs(
        "[worker.\".x\"]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n[worker.\"-y\"]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n",
    );
    assert_eq!(es.len(), 2, "both bad names are reported: {es:?}");
}

#[test]
fn duplicate_instances_are_refused() {
    let es = errs(
        "[worker.g]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\ninstances = [\"a\", \"a\"]\n",
    );
    assert_eq!(es[0].code, Code::Instance);
}

#[test]
fn the_same_name_in_two_kinds_is_a_duplicate_name() {
    let es = errs("[worker.x]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\n[brood.x]\n");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::DuplicateName);
}

#[test]
fn expansion_is_sorted_by_name() {
    let e = ok(r#"
        [worker.zeta]
credentials = { uid = "svc" }
        exec = ["/z"]
        [brood.alpha]
        [forager.mid]
credentials = { uid = "svc" }
        exec = ["/m"]
        [worker.b]
credentials = { uid = "svc" }
        exec = ["/b"]
        instances = ["2", "1"]
    "#);
    let got: Vec<_> = e.frames.iter().map(|(n, k, _)| (n.as_str(), *k)).collect();
    assert_eq!(
        got,
        [
            ("alpha", Kind::Brood),
            ("b@1", Kind::Worker),
            ("b@2", Kind::Worker),
            ("mid", Kind::Forager),
            ("zeta", Kind::Worker),
        ]
    );
}

#[test]
fn an_instances_key_on_a_forager_or_brood_is_refused() {
    let es = errs(
        "[forager.f]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\ninstances = [\"a\"]\n[brood.b]\ninstances = [\"a\"]\n",
    );
    assert_eq!(es.len(), 2, "{es:?}");
    assert!(es.iter().all(|e| e.code == Code::BadValue), "{es:?}");
    assert!(es.iter().any(|e| e.key == "forager.f.instances"), "{es:?}");
    // A template that brings `instances` to a forager is refused too.
    let es = errs(
        "[template.t]\ninstances = [\"a\"]\n[forager.f]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\ntemplate = \"t\"\n",
    );
    assert_eq!(es[0].key, "forager.f.instances");
}

#[test]
fn instance_of_records_the_template_frame_name() {
    // The expanded name carries the instanced frame's name before the `@`; resolve turns it
    // into `instance_of`. Instances inherited from a template expand the same way.
    let e = ok(r#"
        [template.tty]
        exec = ["/sbin/agetty", "%i"]
        instances = ["tty1"]
        [worker.getty]
credentials = { uid = "svc" }
        template = "tty"
    "#);
    let names: Vec<_> = e.frames.iter().map(|(n, _, _)| n.as_str()).collect();
    assert_eq!(names, ["getty@tty1"]);
    let m = qinit_frames::resolve::resolve(&e, &qinit_frames::layers::Enable::default())
        .expect("resolves")
        .model;
    assert_eq!(m.nodes[0].instance_of.as_deref(), Some("getty"));
}

#[test]
fn errors_in_different_frames_are_all_reported() {
    let es = errs(
        "[worker.a]\ncredentials = { uid = \"svc\" }\nready = \"banana\"\n[worker.b]\ncredentials = { uid = \"svc\" }\ntemplate = \"none\"\n",
    );
    assert_eq!(es.len(), 2, "{es:?}");
}

#[test]
fn a_template_cannot_smuggle_forbidden_keys_into_a_brood() {
    let es = errs("[template.t]\nexec = [\"/x\"]\n[brood.b]\ntemplate = \"t\"\n");
    assert_eq!(es[0].code, Code::BadValue);
    assert_eq!(es[0].key, "brood.b.exec");
}

#[test]
fn an_error_carries_the_layer_that_set_the_key() {
    let mut m = merged("[worker.a]\ncredentials = { uid = \"svc\" }\nready = \"banana\"\n");
    let origin = Origin {
        layer: "etc".into(),
        file: "/etc/qinit/a.toml".into(),
        template: None,
    };
    m.provenance
        .insert(FrameKey::new("worker", "a", &[]), origin);
    let es = expand(&m).expect_err("refused");
    assert_eq!(es[0].layer.as_deref(), Some("etc"));
    assert_eq!(
        es[0].file.as_deref(),
        Some(std::path::Path::new("/etc/qinit/a.toml"))
    );
}

#[test]
fn an_empty_instance_list_is_an_instance_error() {
    let es = errs("[worker.g]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\ninstances = []\n");
    assert_eq!(es.len(), 1, "{es:?}");
    assert_eq!(es[0].code, Code::Instance);
    assert_eq!(es[0].key, "worker.g.instances");
    assert!(es[0].detail.contains("disable = true"), "{}", es[0].detail);
    // An empty list inherited from a template is refused the same way.
    let es = errs(
        "[template.t]\ninstances = []\n[worker.g]\ncredentials = { uid = \"svc\" }\nexec = [\"/x\"]\ntemplate = \"t\"\n",
    );
    assert_eq!(
        (es[0].code, es[0].key.as_str()),
        (Code::Instance, "worker.g.instances")
    );
}

#[test]
fn name_length_is_exact_at_96_bytes() {
    let name = |n: usize| "a".repeat(n);
    let one = |n: usize| {
        format!(
            "[worker.{}]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/x\"]\n",
            name(n)
        )
    };
    assert_eq!(ok(&one(96)).frames[0].0.len(), 96);
    assert_eq!(errs(&one(97))[0].code, Code::BadName);
    // `<base>@<instance>` counts as a whole: 90 + 1 + 5 is 96, one more byte is 97.
    let inst = |i: &str| {
        format!(
            "[worker.{}]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/x\"]\ninstances = [\"{i}\"]\n",
            name(90)
        )
    };
    assert_eq!(ok(&inst("bbbbb")).frames[0].0.len(), 96);
    assert_eq!(errs(&inst("bbbbbb"))[0].code, Code::BadName);
}

#[test]
fn a_node_name_that_is_a_cgroup_interface_word_is_refused() {
    let worker = |name: &str| {
        format!("[worker.{name}]\ncredentials = {{ uid = \"svc\" }}\nexec = [\"/a\"]\n")
    };
    for name in [
        "memory.max",
        "cgroup.procs",
        "pids.x",
        "io.weight",
        "irq.pressure",
    ] {
        let es = errs(&worker(&format!("\"{name}\"")));
        assert_eq!(es.len(), 1, "{name}: {es:?}");
        assert_eq!(es[0].code, Code::BadName, "{name}: {es:?}");
        assert!(es[0].detail.contains("reserved"), "{name}: {es:?}");
    }
    // A word that only starts like one is fine.
    ok(&worker("memoryd"));
    ok(&worker("\"iod.main\""));
}

#[test]
fn an_instance_name_that_is_a_cgroup_interface_word_is_refused() {
    let es = errs(
        "[worker.\"memory.x\"]\ncredentials = { uid = \"svc\" }\nexec = [\"/a\"]\ninstances = [\"a\"]\n",
    );
    assert!(es.iter().all(|e| e.code == Code::BadName), "{es:?}");
    assert!(!es.is_empty());
}
