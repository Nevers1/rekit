//! Keys and tokens that were committed by accident.
//!
//! Two passes: a table of shaped credentials (AWS, GitHub, Stripe, private
//! keys and so on), then an entropy pass over quoted strings that matched no
//! rule at all — the second pass is what catches a token format nobody has
//! written a rule for yet.
//!
//! Values are masked by default. A report that prints a live key in full is a
//! report that has just leaked it a second time, into a chat transcript or a
//! CI log; `reveal` exists for the case where the value is already known dead.

use anyhow::Result;
use regex::Regex;
use std::sync::OnceLock;

use crate::gather::{cap, gather};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    fn parse(text: &str) -> Option<Severity> {
        match text.trim().to_lowercase().as_str() {
            "" | "low" | "низко" => Some(Severity::Low),
            "medium" | "средне" => Some(Severity::Medium),
            "high" | "высоко" => Some(Severity::High),
            "critical" | "критично" => Some(Severity::Critical),
            _ => None,
        }
    }
}

struct Rule {
    name: &'static str,
    pattern: &'static str,
    severity: Severity,
}

/// The table, copied from what the shapes actually look like in the wild
/// rather than from a specification: a prefix, a length, a character set.
const RULES: &[Rule] = &[
    Rule {
        name: "AWS access key ID",
        pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "AWS secret key",
        pattern: r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})"#,
        severity: Severity::Critical,
    },
    Rule {
        name: "Google API key",
        pattern: r"\bAIza[0-9A-Za-z\-_]{35}\b",
        severity: Severity::High,
    },
    Rule {
        name: "GCP service account",
        pattern: r#""type"\s*:\s*"service_account""#,
        severity: Severity::Critical,
    },
    Rule {
        name: "Google OAuth client secret",
        pattern: r"\bGOCSPX-[A-Za-z0-9_-]{28}\b",
        severity: Severity::High,
    },
    Rule {
        name: "GitHub token",
        pattern: r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "GitHub fine-grained PAT",
        pattern: r"\bgithub_pat_[A-Za-z0-9_]{82}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "GitLab PAT",
        pattern: r"\bglpat-[A-Za-z0-9_-]{20}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "Slack token",
        pattern: r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "Slack webhook",
        pattern: r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
        severity: Severity::High,
    },
    Rule {
        name: "Stripe live secret",
        pattern: r"\b[rs]k_live_[A-Za-z0-9]{24,}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "SendGrid key",
        pattern: r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
        severity: Severity::High,
    },
    Rule {
        name: "Twilio key",
        pattern: r"\bSK[0-9a-fA-F]{32}\b",
        severity: Severity::Medium,
    },
    Rule {
        name: "Mailgun key",
        pattern: r"\bkey-[0-9a-zA-Z]{32}\b",
        severity: Severity::Medium,
    },
    Rule {
        name: "npm token",
        pattern: r"\bnpm_[A-Za-z0-9]{36}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "PyPI token",
        pattern: r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "OpenAI key",
        pattern: r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "Anthropic key",
        pattern: r"\bsk-ant-[A-Za-z0-9_-]{32,}\b",
        severity: Severity::Critical,
    },
    Rule {
        name: "Shopify token",
        pattern: r"\bshpat_[0-9a-fA-F]{32}\b",
        severity: Severity::High,
    },
    Rule {
        name: "Discord webhook",
        pattern: r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
        severity: Severity::High,
    },
    Rule {
        name: "Telegram bot token",
        pattern: r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
        severity: Severity::High,
    },
    Rule {
        name: "Private key",
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        severity: Severity::Critical,
    },
    Rule {
        name: "JWT",
        pattern: r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}",
        severity: Severity::Low,
    },
    Rule {
        name: "Basic auth in a URL",
        pattern: r"//[^/\s:@]{2,}:[^/\s@]{2,}@[a-zA-Z0-9.-]+",
        severity: Severity::High,
    },
    Rule {
        name: "Firebase/FCM key",
        pattern: r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",
        severity: Severity::Medium,
    },
    Rule {
        name: "Heroku key",
        pattern: r#"(?i)\bheroku[a-z0-9_]{0,10}["'\s:=]+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"#,
        severity: Severity::High,
    },
    Rule {
        name: "Password in code",
        pattern: r#"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*["']([^"'\s]{8,80})["']"#,
        severity: Severity::Medium,
    },
];

/// A quoted run long enough to be a credential rather than a word.
const ENTROPY_TOKEN: &str = r#"["'`]([A-Za-z0-9+/=_-]{24,120})["'`]"#;

#[derive(Debug, Clone)]
pub struct Request {
    pub path: String,
    pub min_severity: String,
    /// Shannon entropy threshold; 0 disables the second pass.
    pub entropy: f64,
    pub reveal: bool,
    pub limit: usize,
}

struct Hit {
    rule: String,
    severity: Severity,
    value: String,
    at: String,
    context: String,
}

pub fn run(req: &Request) -> Result<String> {
    let min = Severity::parse(&req.min_severity)
        .ok_or_else(|| anyhow::anyhow!("minSeverity: use critical, high, medium or low"))?;
    let limit = req.limit.clamp(1, 100_000);

    let gathered = gather(&req.path)?;
    if gathered.srcs.is_empty() {
        return Ok(format!(
            "nothing to scan: {}{}",
            req.path,
            if gathered.skipped > 0 {
                format!(" ({} skipped)", gathered.skipped)
            } else {
                String::new()
            }
        ));
    }

    let mut hits: Vec<Hit> = Vec::new();
    // Deduplication is by value, not by `rule|value`: a Stripe key that also
    // looks like a high-entropy string is one finding, not two.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for src in &gathered.srcs {
        for (rule, regex) in RULES.iter().zip(compiled()) {
            if rule.severity > min || hits.len() >= limit {
                continue;
            }
            for caps in regex.captures_iter(&src.text) {
                // A rule with a capture group names the part that matters;
                // `password = "hunter2"` should report `hunter2`, not the
                // assignment around it.
                let value = match caps.get(1).filter(|group| group.as_str().len() >= 8) {
                    Some(group) => group.as_str().to_string(),
                    None => caps[0].to_string(),
                };
                if !seen.insert(value.clone()) {
                    continue;
                }
                let line = src.line_of(caps.get(0).map(|m| m.start()).unwrap_or(0));
                hits.push(Hit {
                    rule: rule.name.to_string(),
                    severity: rule.severity,
                    value,
                    at: format!("{}:{line}", src.name),
                    context: src.line_text(line),
                });
                if hits.len() >= limit {
                    break;
                }
            }
        }
    }

    // The entropy pass can only ever produce a low-severity finding, so it is
    // pointless work when the caller asked for critical material only.
    let mut entropy_hits = 0usize;
    if req.entropy > 0.0 && min == Severity::Low {
        let regex = Regex::new(ENTROPY_TOKEN).expect("static pattern");
        for src in &gathered.srcs {
            for caps in regex.captures_iter(&src.text) {
                if hits.len() >= limit {
                    break;
                }
                let value = caps[1].to_string();
                // A long hex run is a hash or a UUID, not a secret: its
                // entropy is high but there is nothing to use it for.
                if seen.contains(&value) || is_hex(&value) {
                    continue;
                }
                let entropy = shannon(&value);
                if entropy < req.entropy {
                    continue;
                }
                seen.insert(value.clone());
                let line = src.line_of(caps.get(0).map(|m| m.start()).unwrap_or(0));
                hits.push(Hit {
                    rule: format!("high entropy ({entropy:.2})"),
                    severity: Severity::Low,
                    value,
                    at: format!("{}:{line}", src.name),
                    context: src.line_text(line),
                });
                entropy_hits += 1;
            }
        }
    }

    if hits.is_empty() {
        return Ok(format!(
            "no secrets found in {}\nfiles: {}{}{}",
            req.path,
            gathered.srcs.len(),
            gathered
                .note
                .as_ref()
                .map(|note| format!(" ({note})"))
                .unwrap_or_default(),
            if gathered.skipped > 0 {
                format!(", skipped: {}", gathered.skipped)
            } else {
                String::new()
            }
        ));
    }

    let mut out = format!(
        "# {}\nhits: {} (patterns: {}, entropy: {}){}\nfiles: {}{}{}\n",
        req.path,
        hits.len(),
        hits.len() - entropy_hits,
        entropy_hits,
        if req.reveal {
            ", values shown in full"
        } else {
            ", values masked (reveal=true to show them)"
        },
        gathered.srcs.len(),
        gathered
            .note
            .as_ref()
            .map(|note| format!(" ({note})"))
            .unwrap_or_default(),
        if gathered.skipped > 0 {
            format!(", skipped: {}", gathered.skipped)
        } else {
            String::new()
        }
    );

    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ] {
        if !included(severity, min) {
            continue;
        }
        let group: Vec<&Hit> = hits.iter().filter(|hit| hit.severity == severity).collect();
        if group.is_empty() {
            continue;
        }
        out.push_str(&format!("\n## {} ({})\n", severity.label(), group.len()));
        for hit in group.iter().take(40) {
            let shown = if req.reveal {
                hit.value.clone()
            } else {
                mask(&hit.value)
            };
            // The context line usually contains the value too, so masking only
            // the value line would defeat the mask entirely.
            let context = if req.reveal {
                hit.context.clone()
            } else {
                hit.context.replace(&hit.value, &mask(&hit.value))
            };
            out.push_str(&format!(
                "  {}: {}\n      {}\n      {}\n",
                hit.rule, shown, hit.at, context
            ));
        }
        if group.len() > 40 {
            out.push_str(&format!("  ... {} more\n", group.len() - 40));
        }
    }

    Ok(cap(&out, 400))
}

/// Is this severity at least as serious as the requested floor?
///
/// The enum is ordered from most to least serious, so "at least this bad"
/// means numerically less than or equal.
fn included(severity: Severity, floor: Severity) -> bool {
    severity <= floor
}

/// Compile the table once per process: the same patterns are used for every
/// file in a directory walk.
fn compiled() -> &'static Vec<Regex> {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .map(|rule| Regex::new(rule.pattern).expect("static pattern"))
            .collect()
    })
}

fn is_hex(text: &str) -> bool {
    text.len() >= 24 && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// Shannon entropy in bits per character.
fn shannon(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for ch in text.chars() {
        *counts.entry(ch).or_default() += 1;
    }
    let len = text.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Enough of a value to recognise it, not enough to use it.
fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 12 {
        let head: String = chars.iter().take(2).collect();
        let tail: String = chars.iter().skip(chars.len().saturating_sub(2)).collect();
        let dots = "\u{2022}".repeat(chars.len().saturating_sub(4).max(3));
        format!("{head}{dots}{tail}")
    } else {
        let head: String = chars.iter().take(6).collect();
        let tail: String = chars.iter().skip(chars.len() - 4).collect();
        format!("{head}{}{tail}", "\u{2022}".repeat(8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gather::Src;

    #[test]
    fn the_rule_table_compiles() {
        assert_eq!(compiled().len(), RULES.len());
    }

    #[test]
    fn a_live_stripe_key_is_matched_although_no_fixture_contains_one() {
        // Built at runtime: a literal `sk_live_...` in the repository would be
        // blocked by GitHub's push protection, which is a good default.
        let key = format!("{}{}", "sk_", "live_51H8xkLmnopqrstuvwxyz012345");
        let regex = compiled()
            .iter()
            .zip(RULES)
            .find(|(_, rule)| rule.name == "Stripe live secret")
            .map(|(regex, _)| regex)
            .unwrap();
        assert!(regex.is_match(&format!("const k = \"{key}\";")));
        assert!(mask(&key).starts_with("sk_liv"));
        assert!(!mask(&key).contains("51H8xk"));
    }

    #[test]
    fn a_shaped_key_is_found_with_its_line() {
        let src = Src::new(
            "config.js".into(),
            "const region = 'eu';\nconst key = 'AKIAIOSFODNN7EXAMPLE';\n".into(),
        );
        assert_eq!(src.line_of(30), 2);
        assert!(compiled()[0].is_match(&src.text));
    }

    #[test]
    fn a_password_rule_reports_the_value_not_the_assignment() {
        let regex = compiled()
            .iter()
            .zip(RULES)
            .find(|(_, rule)| rule.name == "Password in code")
            .map(|(regex, _)| regex)
            .unwrap();
        let caps = regex.captures(r#"password = "hunter2hunter2""#).unwrap();
        assert_eq!(&caps[1], "hunter2hunter2");
    }

    #[test]
    fn entropy_separates_a_token_from_prose() {
        assert!(shannon("dGhpcyBpcyBhIHNlY3JldCBrZXk") > 4.0);
        assert!(shannon("aaaaaaaaaaaaaaaaaaaaaaaa") < 1.0);
    }

    #[test]
    fn long_hex_is_not_a_secret() {
        assert!(is_hex(
            "87495cae027bc7cf6dccb5af1c4eb50e7b4f278f8756b2e8c8ee4a0343ace255"
        ));
        assert!(!is_hex("sk-proj-abcdefghijklmnopqrstuvwxyz012345"));
    }

    #[test]
    fn masking_leaves_a_recognisable_fingerprint() {
        let masked = mask("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKIAIO"));
        assert!(masked.ends_with("MPLE"));
        assert!(masked.contains('\u{2022}'));
        assert!(!masked.contains("IOSFODNN7EX"));

        // A short value is still masked, and never shorter than the original.
        let short = mask("abcdef");
        assert!(short.chars().count() >= 6);
        assert!(short.contains('\u{2022}'));
    }

    #[test]
    fn the_severity_floor_keeps_more_serious_findings() {
        assert!(included(Severity::Critical, Severity::Low));
        assert!(included(Severity::Low, Severity::Low));
        assert!(included(Severity::Critical, Severity::Critical));
        assert!(!included(Severity::High, Severity::Critical));
        assert!(!included(Severity::Low, Severity::Medium));
    }

    #[test]
    fn severity_parsing_accepts_the_names_in_both_languages() {
        assert_eq!(Severity::parse("critical"), Some(Severity::Critical));
        assert_eq!(Severity::parse("НИЗКО"), Some(Severity::Low));
        assert_eq!(Severity::parse("nope"), None);
    }
}
