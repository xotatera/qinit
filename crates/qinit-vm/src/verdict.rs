// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Strict guest verdicts, closed by `QINIT-VM <suite> END <case-count>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub case: String,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub verdicts: Vec<Verdict>,
    pub finished: bool,
    pub expected: Option<usize>,
    pub malformed: bool,
}

/// The verdicts of `suite`; unrelated boot noise is ignored.
#[must_use]
pub fn parse(suite: &str, serial: &str) -> Report {
    let mut r = Report {
        verdicts: Vec::new(),
        finished: false,
        expected: None,
        malformed: false,
    };
    let prefix = format!("QINIT-VM {suite} ");
    for line in serial.lines().map(|l| l.trim_end_matches('\r')) {
        let Some(rest) = line.strip_prefix(&prefix) else {
            continue;
        };
        let mut parts = rest.splitn(3, ' ');
        let case = parts.next().unwrap_or("");
        let word = parts.next();
        let detail = parts.next();
        if case == "END" {
            r.malformed |= r.finished || detail.is_some();
            r.finished = true;
            r.expected = word.and_then(|n| n.parse().ok());
            r.malformed |= r.expected.is_none();
            continue;
        }
        if r.finished || case.is_empty() {
            r.malformed = true;
        }
        let outcome = match (word, detail) {
            (Some("PASS"), None) => Outcome::Pass,
            (Some("FAIL"), d) => Outcome::Fail(d.unwrap_or("").to_string()),
            _ => {
                r.malformed = true;
                continue;
            }
        };
        r.verdicts.push(Verdict {
            case: case.to_string(),
            outcome,
        });
    }
    r
}

/// Accept exactly the declared number of distinct, well-formed passes.
pub fn judge(suite: &str, r: &Report) -> Result<usize, String> {
    if !r.finished {
        return Err(format!("suite {suite} never finished (crash or hang)"));
    }
    let mut cases = std::collections::BTreeSet::new();
    for v in &r.verdicts {
        if !cases.insert(&v.case) {
            return Err(format!("suite {suite} duplicate case {}", v.case));
        }
        if let Outcome::Fail(detail) = &v.outcome {
            return Err(format!("suite {suite} failed: {}: {detail}", v.case));
        }
    }
    if r.malformed {
        return Err(format!("suite {suite} garbled verdict or END count"));
    }
    if r.verdicts.is_empty() {
        return Err(format!("suite {suite} reported no case"));
    }
    if r.expected != Some(cases.len()) {
        return Err(format!(
            "suite {suite} missing or extra case: expected {:?}, got {}",
            r.expected,
            cases.len()
        ));
    }
    Ok(cases.len())
}
