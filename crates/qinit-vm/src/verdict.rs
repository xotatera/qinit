// SPDX-FileCopyrightText: 2026 Xota Tera
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading a guest's verdict lines: `QINIT-VM <suite> <case> PASS`, `QINIT-VM <suite> <case>
//! FAIL <detail>` and the closing `QINIT-VM <suite> END`. A suite without its END line crashed
//! or hung, and failed.
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
}

/// The verdicts of `suite` in `serial`; lines of other suites and boot noise are ignored.
#[must_use]
pub fn parse(suite: &str, serial: &str) -> Report {
    let mut r = Report {
        verdicts: Vec::new(),
        finished: false,
    };
    let prefix = format!("QINIT-VM {suite} ");
    for line in serial.lines().map(|l| l.trim_end_matches('\r')) {
        let Some(rest) = line.strip_prefix(&prefix) else {
            continue;
        };
        if rest == "END" {
            r.finished = true;
            continue;
        }
        let mut parts = rest.splitn(3, ' ');
        let (Some(case), Some(word)) = (parts.next(), parts.next()) else {
            continue;
        };
        let outcome = match word {
            "PASS" => Outcome::Pass,
            "FAIL" => Outcome::Fail(parts.next().unwrap_or("").to_string()),
            _ => continue,
        };
        r.verdicts.push(Verdict {
            case: case.to_string(),
            outcome,
        });
    }
    r
}

/// `Ok(passed cases)` when the suite finished with at least one case and no failure.
pub fn judge(suite: &str, r: &Report) -> Result<usize, String> {
    if !r.finished {
        return Err(format!(
            "suite {suite} never finished (crash or hang); {} case(s) reported",
            r.verdicts.len()
        ));
    }
    let failed: Vec<String> = r
        .verdicts
        .iter()
        .filter_map(|v| match &v.outcome {
            Outcome::Fail(d) => Some(format!("{}: {d}", v.case)),
            Outcome::Pass => None,
        })
        .collect();
    if !failed.is_empty() {
        return Err(format!("suite {suite} failed: {}", failed.join("; ")));
    }
    if r.verdicts.is_empty() {
        return Err(format!("suite {suite} reported no case"));
    }
    Ok(r.verdicts.len())
}
