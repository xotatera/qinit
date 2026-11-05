// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later
//! TOML text for single values and keys, through `toml_edit`.
//!
//! `toml` serialises documents, not a lone value (a top-level array is refused), so a value is
//! converted to a `toml_edit::Value` and printed in its default inline form: strings quoted,
//! arrays as `[a, b]`, tables as `{ k = v }`.
use toml_edit::{Array, InlineTable, Key, Value};

/// `v` as an inline TOML value.
#[must_use]
pub fn value(v: &toml::Value) -> String {
    let mut e = edit_value(v);
    e.decor_mut().clear();
    e.to_string()
}

/// `key` as a TOML key: bare when it can be, quoted otherwise.
#[must_use]
pub fn key(key: &str) -> String {
    Key::new(key).to_string()
}

/// `s` as a TOML string.
#[must_use]
pub fn string(s: &str) -> String {
    Value::from(s).to_string()
}

fn edit_value(v: &toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::from(s.as_str()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::from(*b),
        toml::Value::Datetime(d) => d
            .to_string()
            .parse::<toml_edit::Datetime>()
            .map_or_else(|_| Value::from(d.to_string()), Value::from),
        toml::Value::Array(items) => {
            let mut a: Array = items.iter().map(edit_value).collect();
            a.fmt();
            Value::Array(a)
        }
        toml::Value::Table(t) => {
            let mut it = InlineTable::new();
            for (k, v) in t {
                it.insert(k, edit_value(v));
            }
            it.fmt();
            Value::InlineTable(it)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{key, value};

    #[test]
    fn values_print_inline() {
        let t: toml::Table = r#"
s = "a\"b"
n = 63
a = ["x", 1]
t = { pipe = "logd", n = [1, 2] }
e = []
"#
        .parse()
        .unwrap();
        assert_eq!(value(&t["s"]), r#"'a"b'"#);
        assert_eq!(value(&t["n"]), "63");
        assert_eq!(value(&t["a"]), r#"["x", 1]"#);
        assert_eq!(value(&t["t"]), r#"{ n = [1, 2], pipe = "logd" }"#);
        assert_eq!(value(&t["e"]), "[]");
        assert_eq!(key("getty"), "getty");
        assert_eq!(key("a.b"), "\"a.b\"");
    }
}
