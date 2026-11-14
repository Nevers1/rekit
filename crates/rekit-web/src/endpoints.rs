//! What a frontend bundle talks to.
//!
//! An agent looking at a web app or a mobile app's JS assets wants the same
//! five things: absolute URLs, protocol-relative hosts, absolute paths (which
//! are usually API routes), query parameter names, and GraphQL operations. The
//! patterns are deliberately loose — a bundle is minified and quoted in five
//! different ways, so an exact grammar would find nothing — and the junk
//! filter is what keeps the report readable.
//!
//! Nothing is fetched: this reads text and reports strings.

use anyhow::{bail, Context, Result};
use regex::{Regex, RegexBuilder};

use crate::gather::{cap, gather, Groups, Src};

/// An absolute URL. Stops at characters that cannot continue one, which is
/// what keeps `"https://a/b"` from swallowing the closing quote and the comma
/// after it.
const URL: &str = r#"\bhttps?://[^\s"'`<>()\\{}|^\[\]]+"#;
/// `//cdn.example.com/x` — a host without a scheme, common in bundles.
const PROTO_REL: &str = r#"["'`](//[a-zA-Z0-9.-]+\.[a-z]{2,}[^\s"'`<>]*)"#;
/// An absolute path in quotes: the shape of a hardcoded API route. `?` and
/// `&` are part of it — a route with its query string is more useful than the
/// same route cut at the question mark.
const PATH: &str = r#"["'`](/(?:[a-zA-Z0-9_\-~@%.:{}$\[\]?=&]+/?)++)["'`]"#;
const PARAM: &str = r#"[?&]([a-zA-Z_][a-zA-Z0-9_\-\[\]]{1,40})="#;
const GQL: &str = r#"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)"#;
/// A call that names its target as a string literal, whether or not it was
/// quoted — `fetch(`/api`)` has no quotes around the path.
const FETCH: &str =
    r#"\b(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\(\s*["'`]([^"'`\s]+)["'`]"#;

/// Assets that are noise in a report about endpoints.
const JUNK_PATH: &str = r#"(?i)^(?:/(?:img|images|fonts?|css|static|assets?|media|icons?)/.*\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|css|map)|[.#]|/(?:\.well-known/)?(?:favicon\.ico|robots\.txt))$"#;

#[derive(Debug, Clone)]
pub struct Request {
    pub path: String,
    /// all | url | path | param | graphql
    pub kind: String,
    pub filter: Option<String>,
    pub limit: usize,
}

pub fn run(req: &Request) -> Result<String> {
    let kind = {
        let kind = req.kind.trim().to_ascii_lowercase();
        if kind.is_empty() {
            "all".to_string()
        } else {
            kind
        }
    };
    if !matches!(kind.as_str(), "all" | "url" | "path" | "param" | "graphql") {
        bail!("kind: use all, url, path, param or graphql");
    }
    let filter = match req
        .filter
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty())
    {
        Some(pattern) => Some(
            RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .with_context(|| format!("filter {pattern:?} is not a valid regex"))?,
        ),
        None => None,
    };

    let gathered = gather(&req.path)?;
    if gathered.srcs.is_empty() {
        return Ok(format!(
            "nothing to read: {} — {}",
            req.path,
            if gathered.skipped > 0 {
                format!("{} unreadable or binary files", gathered.skipped)
            } else {
                "the file is empty or the directory holds no text".to_string()
            }
        ));
    }

    let limit = req.limit.clamp(1, 20_000);
    let mut urls = Groups::new(limit);
    let mut paths = Groups::new(limit);
    let mut params = Groups::new(limit);
    let mut gql = Groups::new(limit);

    if kind == "all" || kind == "url" {
        collect(
            &gathered.srcs,
            URL,
            &|caps| Some(caps[0].to_string()),
            &mut urls,
        );
        collect(
            &gathered.srcs,
            PROTO_REL,
            &|caps| Some(caps[1].to_string()),
            &mut urls,
        );
    }
    if kind == "all" || kind == "path" {
        let junk = Regex::new(JUNK_PATH).expect("static pattern");
        collect(
            &gathered.srcs,
            PATH,
            &|caps| {
                let candidate = caps[1].to_string();
                (!junk.is_match(&candidate)).then_some(candidate)
            },
            &mut paths,
        );
        // `fetch("/api/x")` is caught by PATH only when the whole path is
        // quoted; a relative one like `fetch("api/x")` is not, and it is the
        // most common form in a modern bundle. A full URL passed to fetch is
        // already in the URL group, so it is not repeated here.
        collect(
            &gathered.srcs,
            FETCH,
            &|caps| {
                let target = caps[1].to_string();
                (!target.starts_with("http://")
                    && !target.starts_with("https://")
                    && !target.starts_with("//"))
                .then_some(target)
            },
            &mut paths,
        );
    }
    if kind == "all" || kind == "param" {
        collect(
            &gathered.srcs,
            PARAM,
            &|caps| Some(caps[1].to_string()),
            &mut params,
        );
    }
    if kind == "all" || kind == "graphql" {
        collect(
            &gathered.srcs,
            GQL,
            &|caps| Some(format!("{} {}", &caps[1], &caps[2])),
            &mut gql,
        );
    }

    if let Some(filter) = &filter {
        urls.retain(filter);
        paths.retain(filter);
        params.retain(filter);
        gql.retain(filter);
    }

    let total_bytes: usize = gathered.srcs.iter().map(|src| src.text.len()).sum();
    let found = urls.len() + paths.len() + params.len() + gql.len();

    let mut out = format!(
        "# {}\nfiles: {}, read: {} KB{}{}{}\n",
        req.path,
        gathered.srcs.len(),
        total_bytes / 1024,
        gathered
            .note
            .as_ref()
            .map(|note| format!(" ({note})"))
            .unwrap_or_default(),
        if gathered.skipped > 0 {
            format!(", skipped: {}", gathered.skipped)
        } else {
            String::new()
        },
        match &req.filter {
            Some(pattern) => format!(", filter: /{pattern}/i"),
            None => String::new(),
        }
    );

    if found == 0 {
        out.push_str("\nnothing found — check that this really is JS/HTML/JSON, or try kind=all\n");
        return Ok(out);
    }

    out.push_str(&urls.dump("URLs", 120));
    out.push_str(&paths.dump("Paths and API routes", 120));
    out.push_str(&params.dump("Parameters", 80));
    out.push_str(&gql.dump("GraphQL", 60));
    Ok(cap(&out, 400))
}

/// Find every match, keep the first place it was seen and a count.
fn collect(
    srcs: &[Src],
    pattern: &str,
    pick: &dyn Fn(&regex::Captures) -> Option<String>,
    out: &mut Groups,
) {
    let regex = Regex::new(pattern).expect("static pattern");
    for src in srcs {
        for caps in regex.captures_iter(&src.text) {
            let Some(value) = pick(&caps) else {
                continue;
            };
            let whole = caps.get(0).map(|m| m.start()).unwrap_or(0);
            // A URL followed by punctuation is still the URL; a bundle that
            // puts it in a template string has a stray `,` or `;` after it
            // more often than not.
            let clean = value
                .trim_end_matches([',', ')', '.', ';', '\\'])
                .to_string();
            if clean.len() < 3 || clean.len() > 400 {
                continue;
            }
            out.add(clean, format!("{}:{}", src.name, src.line_of(whole)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(src: &str) -> Vec<Src> {
        vec![Src::new("app.js".into(), src.into())]
    }

    fn values(srcs: &[Src], pattern: &str, group: usize) -> Vec<String> {
        let regex = Regex::new(pattern).unwrap();
        regex
            .captures_iter(&srcs[0].text)
            .map(|caps| caps[group].to_string())
            .collect()
    }

    #[test]
    fn absolute_and_protocol_relative_urls_are_both_found() {
        let srcs = text(
            r#"const a = "https://api.example.com/v1/login"; const b = "//cdn.example.org/app.js";"#,
        );
        let urls = values(&srcs, URL, 0);
        assert_eq!(urls, vec!["https://api.example.com/v1/login"]);
        let relative = values(&srcs, PROTO_REL, 1);
        assert_eq!(relative, vec!["//cdn.example.org/app.js"]);
    }

    #[test]
    fn trailing_punctuation_is_not_part_of_the_url() {
        let mut groups = Groups::new(10);
        collect(
            &text(r#"["https://example.com/a", "https://example.com/b");]"#),
            URL,
            &|caps| Some(caps[0].to_string()),
            &mut groups,
        );
        let text = groups.dump("URLs", 10);
        assert!(text.contains("https://example.com/a\n"));
        assert!(text.contains("https://example.com/b\n"));
        assert!(!text.contains(".com/a,"));
        assert!(!text.contains(".com/b)"));
    }

    #[test]
    fn a_path_keeps_its_query_string() {
        let srcs = text(r#"x("/api/v2/sessions?page=1&size=20")"#);
        let paths = values(&srcs, PATH, 1);
        assert_eq!(paths, vec!["/api/v2/sessions?page=1&size=20"]);
    }

    #[test]
    fn a_fetched_url_is_not_also_a_path() {
        let mut groups = Groups::new(10);
        collect(
            &text(r#"fetch("https://api.example.com/v2/login"); fetch("api/v1/items")"#),
            FETCH,
            &|caps| {
                let target = caps[1].to_string();
                (!target.starts_with("http") && !target.starts_with("//")).then_some(target)
            },
            &mut groups,
        );
        let text = groups.dump("Paths", 10);
        assert!(!text.contains("https://"));
        assert!(text.contains("api/v1/items"));
    }

    #[test]
    fn paths_keep_api_routes_and_drop_images() {
        let mut groups = Groups::new(10);
        let junk = Regex::new(JUNK_PATH).unwrap();
        collect(
            &text(r#"a("/api/v2/users"); b("/assets/logo.png"); c("/favicon.ico")"#),
            PATH,
            &|caps| {
                let candidate = caps[1].to_string();
                (!junk.is_match(&candidate)).then_some(candidate)
            },
            &mut groups,
        );
        let text = groups.dump("Paths", 10);
        assert!(text.contains("/api/v2/users"));
        assert!(!text.contains("logo.png"));
        assert!(!text.contains("favicon"));
    }

    #[test]
    fn a_fetch_argument_is_a_route_even_without_a_leading_slash() {
        let mut groups = Groups::new(10);
        collect(
            &text(r#"fetch("api/v1/items"); axios.post("/api/v1/items")"#),
            FETCH,
            &|caps| Some(caps[1].to_string()),
            &mut groups,
        );
        let text = groups.dump("Paths", 10);
        assert!(text.contains("api/v1/items"));
        assert!(text.contains("/api/v1/items"));
    }

    #[test]
    fn parameters_and_graphql_operations() {
        let srcs = text(r#"f("/x?token=1&user_id=2"); gql("query GetUser { }")"#);
        assert_eq!(values(&srcs, PARAM, 1), vec!["token", "user_id"]);
        let gql = values(&srcs, GQL, 2);
        assert_eq!(gql, vec!["GetUser"]);
    }

    #[test]
    fn the_junk_filter_is_case_insensitive() {
        let junk = Regex::new(JUNK_PATH).unwrap();
        assert!(junk.is_match("/ASSETS/Logo.PNG"));
        assert!(!junk.is_match("/api/users"));
    }
}
