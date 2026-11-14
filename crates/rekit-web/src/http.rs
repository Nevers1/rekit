//! One HTTP request, with everything on it controlled.
//!
//! A webfetch-style tool is GET-only, cannot set headers, cannot send a body
//! and cannot go through a proxy — which rules out exactly the requests that
//! matter when checking whether an endpoint is authenticated: the POST with a
//! JSON body, the one with someone else's cookie, the one through the proxy
//! that reaches the staging host.
//!
//! The request itself is `curl`, spawned as a child. That is a deliberate
//! trade: speaking HTTPS in-process means linking a TLS stack and a large
//! dependency tree into a tool whose whole point is one static binary, and
//! `curl` is already on every machine that would run this.
//!
//! Nothing here follows a redirect to a protocol it was not asked about, and
//! `file://` and friends are rejected before curl ever sees them.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::gather::cap;

const METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
/// What a caller gets when it names no timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 20_000;

#[derive(Debug, Clone)]
pub struct Request {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// A body given as JSON, which also sets the content type.
    pub json: Option<serde_json::Value>,
    pub redirect: bool,
    pub timeout_ms: u64,
    pub proxy: Option<String>,
    pub save: Option<String>,
    /// Print the body alone, without status or headers.
    pub body_only: bool,
}

pub fn run(req: &Request) -> Result<String> {
    let url = req.url.trim();
    if url.is_empty() {
        bail!("url is empty");
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        bail!("url must start with http:// or https:// (this tool speaks HTTP, not file:// or gopher://)");
    }
    let method = {
        let method = req.method.trim().to_ascii_uppercase();
        if method.is_empty() {
            "GET".to_string()
        } else {
            method
        }
    };
    if !METHODS.contains(&method.as_str()) {
        bail!("method: use GET, POST, PUT, PATCH, DELETE, HEAD or OPTIONS");
    }
    if rekit_core::external::which("curl").is_none() {
        bail!("curl is not installed; the http tool uses it for TLS, proxies and redirects");
    }

    let mut headers = req.headers.clone();
    // JSON wins over a raw body when both are given: the caller that passed an
    // object meant it, and silently sending the other one would be a mystery.
    let body: Option<String> = match &req.json {
        Some(value) => {
            if !headers
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case("content-type"))
            {
                headers.push(("Content-Type".to_string(), "application/json".to_string()));
            }
            Some(serde_json::to_string(value)?)
        }
        None => req.body.clone(),
    };
    let sends_body = body.is_some() && method != "GET" && method != "HEAD";

    let timeout = Duration::from_millis(req.timeout_ms.clamp(100, 600_000));
    let workdir = work_dir()?;
    let body_path = workdir.join("request-body");
    let header_path = workdir.join("response-headers");
    let response_path = workdir.join("response-body");
    if let Some(body) = &body {
        fs::write(&body_path, body)
            .with_context(|| format!("cannot write {}", body_path.display()))?;
    }

    // `-w` is the only structured channel curl offers, and the status line is
    // part of the response body unless headers are diverted with `-D`.
    let mut args: Vec<String> = vec![
        "-sS".into(),
        "--max-time".into(),
        format!("{:.3}", timeout.as_secs_f64()),
        "-D".into(),
        header_path.display().to_string(),
        "-o".into(),
        response_path.display().to_string(),
        "-w".into(),
        "%{http_code}\n%{size_download}\n%{time_total}\n%{redirect_url}\n%{url_effective}".into(),
    ];
    if method == "HEAD" {
        args.push("--head".into());
    } else if method != "GET" {
        args.push("-X".into());
        args.push(method.clone());
    }
    for (key, value) in &headers {
        // A header value containing a newline would let the caller inject a
        // second request; curl refuses it too, but the message is clearer here.
        if key.contains('\n') || value.contains('\n') || key.contains('\r') || value.contains('\r')
        {
            bail!("header {key:?} contains a newline");
        }
        args.push("-H".into());
        args.push(format!("{key}: {value}"));
    }
    if sends_body {
        args.push("--data-binary".into());
        args.push(format!("@{}", body_path.display()));
    }
    if req.redirect {
        args.push("-L".into());
        args.push("--max-redirs".into());
        args.push("10".into());
    }
    if let Some(proxy) = req
        .proxy
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        args.push("-x".into());
        args.push(proxy.to_string());
    }
    args.push(url.to_string());

    let started = std::time::Instant::now();
    let out =
        rekit_core::external::capture("curl", &args, timeout + Duration::from_secs(5), &[], None)
            .context("cannot run curl")?;
    let elapsed = started.elapsed();

    if out.timed_out {
        bail!(
            "the request did not finish within {}s{}\ncurl timed out",
            seconds(timeout),
            req.proxy
                .as_deref()
                .map(|proxy| format!(" (proxy {proxy})"))
                .unwrap_or_default()
        );
    }
    if !out.success {
        let detail = out.stderr.trim();
        // curl exits 28 on its own timeout, which is a different thing from
        // the host being unreachable and deserves a different message.
        if detail.contains("Operation timed out") || detail.contains("(28)") {
            bail!(
                "the request did not finish within {}s{}\ncurl timed out after {} ms",
                seconds(timeout),
                req.proxy
                    .as_deref()
                    .map(|proxy| format!(" (proxy {proxy})"))
                    .unwrap_or_default(),
                elapsed.as_millis()
            );
        }
        let reason = if detail.is_empty() {
            "curl exited with an error"
        } else {
            detail
        };
        let proxy = req
            .proxy
            .as_deref()
            .map(|proxy| format!("\nproxy: {proxy}"))
            .unwrap_or_default();
        let elapsed_ms = elapsed.as_millis();
        bail!(
            "the request failed: {reason}\ncheck that the host and the proxy are reachable\
             {proxy}\nelapsed: {elapsed_ms} ms"
        );
    }

    let meta = parse_meta(&out.stdout);
    let headers_text = fs::read_to_string(&header_path).unwrap_or_default();
    let response = fs::read(&response_path).unwrap_or_default();
    let text = String::from_utf8_lossy(&response).to_string();

    if let Some(save) = req.save.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let target = Path::new(save);
        if let Some(parent) = target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).ok();
        }
        fs::write(target, &response).with_context(|| format!("cannot write {save}"))?;
    }
    let _ = fs::remove_dir_all(&workdir);

    if req.body_only {
        return Ok(cap(&text, 300));
    }

    let mut out = format!("# {method} {url}\n## Response\n  {}", meta.summary());
    if meta
        .redirected_to
        .as_deref()
        .is_some_and(|final_url| final_url != url)
    {
        out.push_str(&format!(
            " (redirected to {})",
            meta.redirected_to.as_deref().unwrap_or_default()
        ));
    }
    if let Some(proxy) = req.proxy.as_deref().filter(|p| !p.trim().is_empty()) {
        out.push_str(&format!(" (through {proxy})"));
    }
    let last = last_header_block(&headers_text);
    if !last.is_empty() {
        out.push_str(&format!(
            "\n\n## Headers\n{}",
            cap(&last, 100).replace('\n', "\n  ")
        ));
    }
    // `curl --head` writes the header block where the body would go, so a HEAD
    // response would otherwise print its headers twice.
    if method == "HEAD" {
        out.push_str("\n\n## Body\n  (HEAD: no body)");
    } else {
        out.push_str(&format!("\n\n## Body\n{}", cap(&text, 300)));
    }
    out.push_str(&format!(
        "\n\n## Repeat\n{}",
        repeat_command(
            url,
            &method,
            &headers,
            body.as_deref(),
            req.proxy.as_ref(),
            req.redirect
        )
    ));
    if let Some(save) = req.save.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        out.push_str(&format!("\n\nsaved: {}", Path::new(save).display()));
    }
    Ok(cap(&out, 500))
}

struct Meta {
    status: u16,
    size: u64,
    time_ms: u64,
    redirected_to: Option<String>,
}

impl Meta {
    fn summary(&self) -> String {
        format!(
            "{}  {}  {} ms",
            self.status,
            human_bytes(self.size),
            self.time_ms
        )
    }
}

fn parse_meta(text: &str) -> Meta {
    let mut lines = text.lines();
    let status = lines.next().unwrap_or("0").trim().parse().unwrap_or(0);
    let size = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<f64>()
        .unwrap_or(0.0) as u64;
    let seconds = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<f64>()
        .unwrap_or(0.0);
    let redirected = lines.next().unwrap_or("").trim().to_string();
    let effective = lines.next().unwrap_or("").trim().to_string();
    let url = if effective.is_empty() {
        if redirected.is_empty() {
            None
        } else {
            Some(redirected)
        }
    } else {
        Some(effective)
    };
    Meta {
        status,
        size,
        time_ms: (seconds * 1000.0) as u64,
        redirected_to: url,
    }
}

/// `-D` writes one header block per hop; the last one belongs to the response
/// that was actually returned.
fn last_header_block(text: &str) -> String {
    let normalised = text.replace("\r\n", "\n");
    let blocks: Vec<&str> = normalised
        .split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .collect();
    blocks
        .last()
        .map(|block| {
            block
                .lines()
                .map(str::trim_end)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn repeat_command(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    proxy: Option<&String>,
    redirect: bool,
) -> String {
    let mut parts: Vec<String> = vec!["curl -i".to_string()];
    if method != "GET" && method != "HEAD" {
        parts.push(format!("-X {method}"));
    }
    if method == "HEAD" {
        parts.push("--head".to_string());
    }
    for (key, value) in headers {
        parts.push(format!("-H {}", quote(&format!("{key}: {value}"))));
    }
    if let Some(body) = body.filter(|_| method != "GET" && method != "HEAD") {
        parts.push(format!("--data {}", quote(body)));
    }
    if let Some(proxy) = proxy.filter(|p| !p.trim().is_empty()) {
        parts.push(format!("-x {}", quote(proxy.trim())));
    }
    if redirect {
        parts.push("-L".to_string());
    }
    parts.push(quote(url));
    parts.join(" ")
}

/// Shell-quoted the way a person would type it: single quotes unless the text
/// contains one, in which case the plain form is kept readable.
fn quote(text: &str) -> String {
    if text.contains('\'') {
        format!("\"{}\"", text.replace('"', "\\\""))
    } else {
        format!("'{text}'")
    }
}

/// A duration as a person would say it: `0.7`, `20`.
fn seconds(duration: Duration) -> String {
    format!("{:.1}", duration.as_secs_f64())
        .trim_end_matches(".0")
        .to_string()
}

fn human_bytes(size: u64) -> String {
    match size {
        0..=1023 => format!("{size} B"),
        1024..=1_048_575 => format!("{:.1} KB", size as f64 / 1024.0),
        _ => format!("{:.1} MB", size as f64 / 1_048_576.0),
    }
}

/// A per-run directory, so two concurrent requests cannot overwrite each
/// other's body.
fn work_dir() -> Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let dir =
        rekit_core::resolve::cache_root().join(format!("http-{}-{stamp}", std::process::id()));
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_output_is_parsed_into_a_status_size_and_time() {
        let meta = parse_meta("200\n1234\n0.25\nhttps://a/b\nhttps://a/b");
        assert_eq!(meta.status, 200);
        assert_eq!(meta.size, 1234);
        assert_eq!(meta.time_ms, 250);
        assert_eq!(meta.redirected_to.as_deref(), Some("https://a/b"));
    }

    #[test]
    fn the_last_header_block_wins() {
        let text = "HTTP/1.1 301 Moved\r\nLocation: /b\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
        let last = last_header_block(text);
        assert!(last.starts_with("HTTP/1.1 200 OK"));
        assert!(last.contains("Content-Type: text/html"));
        assert!(!last.contains("301"));
        assert!(!last.contains('\r'));
    }

    #[test]
    fn a_repeat_command_quotes_what_needs_quoting() {
        let command = repeat_command(
            "https://api/x?y=1",
            "POST",
            &[("Authorization".into(), "Bearer abc".into())],
            Some(r#"{"a":1}"#),
            None,
            true,
        );
        assert!(command.contains("-X POST"));
        assert!(command.contains("-H 'Authorization: Bearer abc'"));
        assert!(command.contains("--data '{\"a\":1}'"));
        assert!(command.ends_with("-L 'https://api/x?y=1'"));
    }

    #[test]
    fn a_value_with_a_quote_is_not_single_quoted() {
        let command = repeat_command("https://x/", "GET", &[], None, None, false);
        assert!(command.ends_with("'https://x/'"));
        assert_eq!(quote("it's"), r#""it's""#);
    }

    #[test]
    fn a_body_is_not_sent_with_get_or_head() {
        let command = repeat_command("https://x/", "GET", &[], Some("ignored"), None, true);
        assert!(!command.contains("--data"));
        let command = repeat_command("https://x/", "HEAD", &[], Some("ignored"), None, true);
        assert!(!command.contains("--data"));
    }

    #[test]
    fn a_refused_url_never_reaches_curl() {
        let req = Request {
            url: "file:///etc/passwd".into(),
            method: "GET".into(),
            headers: Vec::new(),
            body: None,
            json: None,
            redirect: true,
            timeout_ms: 1000,
            proxy: None,
            save: None,
            body_only: false,
        };
        assert!(run(&req).unwrap_err().to_string().contains("http://"));
    }

    #[test]
    fn a_header_with_a_newline_is_refused() {
        let req = Request {
            url: "https://example.invalid/".into(),
            method: "GET".into(),
            headers: vec![("X-Test".into(), "a\r\nX-Evil: 1".into())],
            body: None,
            json: None,
            redirect: true,
            timeout_ms: 1000,
            proxy: None,
            save: None,
            body_only: false,
        };
        assert!(run(&req).unwrap_err().to_string().contains("newline"));
    }

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(3 * 1_048_576), "3.0 MB");
    }
}
