//! Reading a JWT, and testing whether its signature means anything.
//!
//! Decoding is the easy half: header and payload are base64url JSON, and any
//! tool can show them. The half that matters is what the token *trusts*:
//! `alg: none`, an `HS*` secret short enough to guess, a `jku`/`x5u` that
//! points at the attacker's key, a `kid` that reaches the filesystem or the
//! database. Those are reported as warnings, because they are the shapes that
//! turn a token into an authentication bypass.
//!
//! HMAC is implemented here rather than pulled in: it is twenty lines over
//! `sha2`, and the alternative was a dependency tree for one function.

use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::digest::{Digest, DynDigest};

use crate::gather::{cap, gather};

#[derive(Debug, Clone)]
pub struct Request {
    /// The token itself, or `None` to find tokens in `path`.
    pub token: Option<String>,
    pub path: Option<String>,
    pub secret: Option<String>,
    pub wordlist: Option<String>,
    /// How many words to try from the wordlist.
    pub limit: usize,
}

#[derive(Debug, Clone, Copy)]
enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    fn from_alg(alg: &str) -> Option<Algorithm> {
        match alg.to_ascii_uppercase().as_str() {
            "HS256" => Some(Algorithm::Sha256),
            "HS384" => Some(Algorithm::Sha384),
            "HS512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }

    fn block_size(self) -> usize {
        match self {
            Algorithm::Sha256 => 64,
            Algorithm::Sha384 | Algorithm::Sha512 => 128,
        }
    }

    fn hasher(self) -> Box<dyn DynDigest> {
        match self {
            Algorithm::Sha256 => Box::new(sha2::Sha256::new()),
            Algorithm::Sha384 => Box::new(sha2::Sha384::new()),
            Algorithm::Sha512 => Box::new(sha2::Sha512::new()),
        }
    }
}

pub fn run(req: &Request) -> Result<String> {
    let token = req
        .token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let path = req
        .path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty());
    let secret = req
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|secret| !secret.is_empty());
    let wordlist = req
        .wordlist
        .as_deref()
        .map(str::trim)
        .filter(|list| !list.is_empty());

    match (token, path) {
        (None, None) => bail!("pass token, or path to look for tokens in"),
        (Some(token), _) => {
            let mut out = report(token, secret)?;
            if let Some(wordlist) = wordlist {
                out.push_str(&format!(
                    "\n\n## Cracking\n{}\n",
                    crack(token, wordlist, req.limit)?
                ));
            }
            Ok(cap(&out, 400))
        }
        (None, Some(path)) => {
            let gathered = gather(path)?;
            let regex = regex::Regex::new(TOKEN).expect("static pattern");
            let mut found: Vec<(String, String)> = Vec::new();
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for src in &gathered.srcs {
                for found_token in regex.find_iter(&src.text) {
                    if found.len() >= 40 {
                        break;
                    }
                    let value = found_token.as_str().to_string();
                    if !seen.insert(value.clone()) {
                        continue;
                    }
                    let line = src.line_of(found_token.start());
                    found.push((format!("{}:{line}", src.name), value));
                }
            }
            if found.is_empty() {
                return Ok(format!(
                    "no JWTs found in {}{}",
                    path,
                    gathered
                        .note
                        .as_ref()
                        .map(|note| format!(" ({note})"))
                        .unwrap_or_default()
                ));
            }

            let mut out = format!(
                "JWTs found: {}{}\n",
                found.len(),
                gathered
                    .note
                    .as_ref()
                    .map(|note| format!(" ({note})"))
                    .unwrap_or_default()
            );
            for (at, value) in &found {
                out.push_str(&format!("\n{}\n{at}\n{value}\n\n", "-".repeat(60)));
                match report(value, secret) {
                    Ok(report) => out.push_str(&report),
                    Err(err) => out.push_str(&format!("  could not read it: {err}")),
                }
                out.push('\n');
            }
            Ok(cap(&out, 600))
        }
    }
}

/// The shape of a JWT: three base64url segments, the first of which is
/// `{"alg":...}` and therefore always starts with `eyJ`.
const TOKEN: &str = r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}";

struct Decoded {
    header: Value,
    payload: Value,
    signature: String,
    parts: Vec<String>,
}

fn decode(token: &str) -> Result<Decoded> {
    let parts: Vec<String> = token.trim().split('.').map(str::to_string).collect();
    if parts.len() < 2 {
        bail!("this is not a JWT: fewer than two dot-separated segments");
    }
    let header: Value =
        serde_json::from_slice(&b64url_decode(&parts[0]).context("header is not base64url")?)
            .context("header does not decode to JSON")?;
    let payload: Value =
        serde_json::from_slice(&b64url_decode(&parts[1]).context("payload is not base64url")?)
            .context("payload does not decode to JSON")?;
    Ok(Decoded {
        header,
        payload,
        signature: parts.get(2).cloned().unwrap_or_default(),
        parts,
    })
}

fn report(token: &str, secret: Option<&str>) -> Result<String> {
    let decoded = decode(token)?;
    let alg = decoded
        .header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();

    let mut out = format!(
        "## Header\n{}\n\n## Payload\n{}",
        serde_json::to_string_pretty(&decoded.header)?,
        serde_json::to_string_pretty(&decoded.payload)?
    );

    let mut claims: Vec<String> = Vec::new();
    let now = unix_now();
    for (key, label) in [("exp", "expires"), ("iat", "issued"), ("nbf", "valid from")] {
        if let Some(value) = decoded.payload.get(key).and_then(Value::as_i64) {
            let diff = value - now;
            let relative = if diff.unsigned_abs() > 86_400 {
                format!("{:.1} days", diff as f64 / 86_400.0)
            } else {
                format!("{:.1} hours", diff as f64 / 3_600.0)
            };
            claims.push(format!(
                "{label}: {} ({})",
                iso8601(value),
                if diff >= 0 {
                    format!("in {relative}")
                } else {
                    format!("expired {} ago", relative.trim_start_matches('-'))
                }
            ));
        }
    }
    for key in ["aud", "iss", "sub"] {
        if let Some(value) = decoded.payload.get(key) {
            let rendered = match value {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            claims.push(format!("{key}: {rendered}"));
        }
    }
    if !claims.is_empty() {
        out.push_str(&format!("\n\n## Claims\n{}", indent(&claims)));
    }

    if let Some(secret) = secret {
        let valid = verify(&decoded, secret)?;
        out.push_str(&format!(
            "\n\n## Signature\n  {}",
            if valid {
                "the signature matches this secret"
            } else {
                "the signature does NOT match this secret"
            }
        ));
    }

    let mut warnings: Vec<String> = Vec::new();
    if alg.eq_ignore_ascii_case("none") {
        warnings.push(
            "alg=none — the signature is not checked, so the token can be rewritten by hand"
                .to_string(),
        );
    }
    if alg.to_ascii_uppercase().starts_with("HS") {
        warnings.push(format!(
            "{alg} — a symmetric secret, so it can be guessed from a wordlist (see wordlist)"
        ));
    }
    if let Some(jku) = decoded.header.get("jku").and_then(Value::as_str) {
        warnings.push(format!(
            "jku={jku} — point this at your own key set and sign with your own key"
        ));
    }
    if let Some(x5u) = decoded.header.get("x5u").and_then(Value::as_str) {
        warnings.push(format!(
            "x5u={x5u} — same trick through a certificate chain"
        ));
    }
    if let Some(kid) = decoded.header.get("kid").and_then(Value::as_str) {
        if kid.contains("..") || kid.contains('/') || kid.contains('\\') {
            warnings.push(format!(
                "kid={kid} — looks like path traversal or SQL injection in kid handling"
            ));
        } else {
            warnings.push(format!(
                "kid={kid} — check whether it is interpolated into SQL or a file path"
            ));
        }
    }
    if decoded.parts.len() < 3 || decoded.signature.is_empty() {
        warnings.push("there is no signature at all".to_string());
    }
    if !warnings.is_empty() {
        out.push_str(&format!(
            "\n\n## What to look at\n{}",
            indent(
                &warnings
                    .iter()
                    .map(|w| format!("- {w}"))
                    .collect::<Vec<_>>()
            )
        ));
    }

    Ok(out)
}

fn verify(decoded: &Decoded, secret: &str) -> Result<bool> {
    let alg = decoded
        .header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(algorithm) = Algorithm::from_alg(alg) else {
        bail!("signature checking is implemented for HS256/384/512, and this is {alg:?}");
    };
    let data = format!("{}.{}", decoded.parts[0], decoded.parts[1]);
    let expected = b64url_encode(&hmac(algorithm, secret.as_bytes(), data.as_bytes()));
    Ok(expected == decoded.signature)
}

fn crack(token: &str, wordlist: &str, limit: usize) -> Result<String> {
    let decoded = decode(token)?;
    let alg = decoded
        .header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(algorithm) = Algorithm::from_alg(alg) else {
        bail!("cracking only makes sense for HS256/384/512, and this is {alg:?}");
    };
    if decoded.signature.is_empty() {
        bail!("the token has no signature to match against");
    }

    let text = std::fs::read_to_string(wordlist)
        .with_context(|| format!("cannot read the wordlist {wordlist}"))?;
    let words: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
    let tries = words.len().min(limit.max(1));
    let data = format!("{}.{}", decoded.parts[0], decoded.parts[1]);
    let started = Instant::now();

    for (index, word) in words.iter().take(tries).enumerate() {
        let signature = b64url_encode(&hmac(algorithm, word.as_bytes(), data.as_bytes()));
        if signature == decoded.signature {
            return Ok(format!(
                "SECRET FOUND: {word:?}\ntried {} of {} in {:.1}s\n\
                 Next: this secret can sign your own tokens — check what rewriting \
                 the claims gains you.",
                index + 1,
                words.len(),
                started.elapsed().as_secs_f64()
            ));
        }
    }

    Ok(format!(
        "no secret found: tried {tries} of {} words in {:.1}s (limit {limit}, raise it if needed)",
        words.len(),
        started.elapsed().as_secs_f64()
    ))
}

/// HMAC as defined by RFC 2104, over whichever SHA-2 the token asks for.
fn hmac(algorithm: Algorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    let block = algorithm.block_size();
    let mut padded = vec![0u8; block];
    if key.len() > block {
        let mut hasher = algorithm.hasher();
        hasher.update(key);
        let digest = hasher.finalize_reset();
        padded[..digest.len()].copy_from_slice(&digest);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let ipad: Vec<u8> = padded.iter().map(|byte| byte ^ 0x36).collect();
    let mut inner = algorithm.hasher();
    inner.update(&ipad);
    inner.update(data);
    let inner_digest = inner.finalize_reset();

    let opad: Vec<u8> = padded.iter().map(|byte| byte ^ 0x5c).collect();
    let mut outer = algorithm.hasher();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finalize().to_vec()
}

fn b64url_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for ch in text.chars() {
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '-' | '+' => 62,
            '_' | '/' => 63,
            '=' => continue,
            _ => bail!("{ch:?} is not a base64url character"),
        };
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            // Only the low bits are still meaningful; keeping the rest would
            // overflow the accumulator after a few characters.
            accumulator &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn b64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let packed = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
        let take = chunk.len() + 1;
        for index in 0..take {
            let sextet = (packed >> (18 - 6 * index)) & 0x3f;
            out.push(ALPHABET[sextet as usize] as char);
        }
    }
    out
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix seconds to `YYYY-MM-DDTHH:MM:SSZ`, without a date library.
///
/// The civil-from-days conversion is Howard Hinnant's; it is short, exact for
/// every date a token can hold, and beats pulling in a calendar crate for one
/// line of output.
fn iso8601(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn indent(lines: &[String]) -> String {
    lines
        .iter()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips() {
        for text in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            let encoded = b64url_encode(text.as_bytes());
            assert_eq!(b64url_decode(&encoded).unwrap(), text.as_bytes());
        }
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        assert!(!b64url_encode(&[0xff, 0xfe]).contains('='));
    }

    #[test]
    fn hmac_matches_the_rfc_4231_vector() {
        // RFC 4231 test case 2, which covers the truncated-key path too.
        let mac = hmac(Algorithm::Sha256, b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_token_that_only_a_weak_secret_signs_is_identified() {
        let token = signed("secret");
        let decoded = decode(&token).unwrap();
        assert!(verify(&decoded, "secret").unwrap());
        assert!(!verify(&decoded, "not-the-secret").unwrap());
        assert_eq!(decoded.payload["sub"], "1234567890");
    }

    #[test]
    fn cracking_finds_the_word_in_a_list() {
        let token = signed("hunter2");
        let dir = std::env::temp_dir().join(format!("rekit-jwt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("words.txt");
        std::fs::write(&list, "password\nletmein\nhunter2\n").unwrap();
        let out = crack(&token, list.to_string_lossy().as_ref(), 100).unwrap();
        assert!(out.contains("SECRET FOUND"));
        assert!(out.contains("hunter2"));
        assert!(out.contains("3 of 3"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_secret_is_reported_as_a_count() {
        let token = signed("hunter2");
        let dir = std::env::temp_dir().join(format!("rekit-jwt-miss-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("words.txt");
        std::fs::write(&list, "password\nletmein\n").unwrap();
        let out = crack(&token, list.to_string_lossy().as_ref(), 100).unwrap();
        assert!(out.contains("no secret found: tried 2 of 2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn alg_none_is_called_out() {
        let header = b64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = b64url_encode(br#"{"sub":"admin"}"#);
        let token = format!("{header}.{payload}.");
        let out = report(&token, None).unwrap();
        assert!(out.contains("alg=none"));
        assert!(out.contains("no signature at all"));
    }

    #[test]
    fn a_kid_with_a_path_is_flagged_as_traversal() {
        let header = b64url_encode(br#"{"alg":"HS256","kid":"../../etc/passwd"}"#);
        let payload = b64url_encode(br#"{"sub":"admin"}"#);
        let out = report(&format!("{header}.{payload}.sig"), None).unwrap();
        assert!(out.contains("path traversal"));
    }

    #[test]
    fn claims_are_human_readable() {
        // 2024-01-01T00:00:00Z, long past, so the wording is "expired".
        let out = report(&signed_with_claims(1_704_067_200), None).unwrap();
        assert!(out.contains("expires: 2024-01-01T00:00:00Z"));
        assert!(out.contains("expired"));
    }

    #[test]
    fn timestamps_are_iso_8601() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(iso8601(1_704_067_200), "2024-01-01T00:00:00Z");
        // A leap day, which is where a hand-rolled calendar usually breaks.
        assert_eq!(iso8601(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    fn signed(secret: &str) -> String {
        signed_with_claims_at(secret, 1_516_239_022)
    }

    fn signed_with_claims(exp: i64) -> String {
        signed_with_claims_at("secret", exp)
    }

    fn signed_with_claims_at(secret: &str, exp: i64) -> String {
        let header = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = b64url_encode(format!(r#"{{"sub":"1234567890","exp":{exp}}}"#).as_bytes());
        let data = format!("{header}.{payload}");
        let signature = b64url_encode(&hmac(Algorithm::Sha256, secret.as_bytes(), data.as_bytes()));
        format!("{data}.{signature}")
    }
}
