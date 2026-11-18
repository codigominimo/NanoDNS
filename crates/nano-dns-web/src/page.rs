//! Server-rendered HTML for the management dashboard.
//!
//! All dynamic values are escaped before being inserted, so a malicious
//! instance name or queried domain can never inject markup.

use nano_dns_core::model::StatsSnapshot;

/// Values needed to render the dashboard.
pub(super) struct PageData<'a> {
    pub(super) instance: &'a str,
    pub(super) version: &'a str,
    pub(super) uptime_secs: u64,
    pub(super) resolver_mode: &'a str,
    pub(super) stats: Option<StatsSnapshot>,
}

/// Render the complete HTML document.
pub(super) fn render(data: &PageData<'_>) -> String {
    let instance = escape(data.instance);
    let (stats_html, stats_note) = match &data.stats {
        Some(snapshot) => (statistics_section(snapshot), ""),
        None => (
            String::new(),
            "<p class=\"notice\">Statistics are disabled. Enable <code>stats.enabled</code> \
             and build with the <code>statistics</code> feature to see query data.</p>",
        ),
    };

    let mut html = String::with_capacity(6144);
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str(&format!("<title>{instance} &middot; NanoDNS</title>\n"));
    html.push_str(STYLE);
    html.push_str("</head>\n<body>\n<main>\n");

    html.push_str(&format!(
        "<header><h1>NanoDNS <span class=\"muted\">&mdash; {instance}</span></h1>\
         <p class=\"subtitle\">Lightweight, modular DNS server</p></header>\n"
    ));

    html.push_str("<section class=\"cards\">\n");
    html.push_str(&card("Status", "running", "ok"));
    html.push_str(&card("Version", data.version, ""));
    html.push_str(&card("Uptime", &format!("{} s", data.uptime_secs), ""));
    html.push_str(&card("Resolver", data.resolver_mode, ""));
    html.push_str("</section>\n");

    html.push_str(stats_note);
    html.push_str(&stats_html);

    html.push_str("</main>\n<footer>NanoDNS &middot; local management interface</footer>\n");
    html.push_str("</body>\n</html>\n");
    html
}

/// Render one summary card.
fn card(label: &str, value: &str, class: &str) -> String {
    format!(
        "<div class=\"card {}\"><div class=\"label\">{}</div>\
         <div class=\"value\">{}</div></div>\n",
        class,
        escape(label),
        escape(value)
    )
}

/// Render the statistics section with counters and breakdown tables.
fn statistics_section(stats: &StatsSnapshot) -> String {
    let mut html = String::with_capacity(4096);
    html.push_str("<section>\n<h2>Overview</h2>\n<div class=\"cards\">\n");
    html.push_str(&card("Queries", &stats.total_queries.to_string(), ""));
    html.push_str(&card("Allowed", &stats.allowed.to_string(), "good"));
    html.push_str(&card("Blocked", &stats.blocked.to_string(), "bad"));
    html.push_str(&card("Cache hits", &stats.cache_hits.to_string(), ""));
    html.push_str(&card("Errors", &stats.errors.to_string(), ""));
    html.push_str("</div>\n</section>\n");

    html.push_str("<section class=\"grid\">\n");
    html.push_str(&table(
        "Response codes",
        &["Code", "Count"],
        stats
            .response_codes
            .iter()
            .map(|(code, count)| (format!("{} ({code})", response_code_name(*code)), *count)),
    ));
    html.push_str(&table(
        "Query types",
        &["Type", "Count"],
        stats
            .query_types
            .iter()
            .map(|(kind, count)| (format!("{} ({kind})", query_type_name(*kind)), *count)),
    ));
    html.push_str(&table(
        "Transports",
        &["Transport", "Count"],
        stats
            .transports
            .iter()
            .map(|(name, count)| (name.clone(), *count)),
    ));
    html.push_str(&table(
        "Top domains",
        &["Domain", "Count"],
        stats
            .top_domains
            .iter()
            .map(|(name, count)| (name.clone(), *count)),
    ));
    html.push_str("</section>\n");
    html
}

/// Render a two-column table with a placeholder when empty.
fn table(
    title: &str,
    headings: &[&str; 2],
    entries: impl Iterator<Item = (String, u64)>,
) -> String {
    let rows = entries
        .map(|(name, count)| {
            format!(
                "<tr><td>{}</td><td class=\"num\">{count}</td></tr>",
                escape(&name)
            )
        })
        .collect::<String>();
    let body = if rows.is_empty() {
        "<tr><td colspan=\"2\" class=\"empty\">No data yet</td></tr>".to_owned()
    } else {
        rows
    };
    format!(
        "<div class=\"panel\"><h2>{}</h2><table><thead><tr><th>{}</th>\
         <th class=\"num\">{}</th></tr></thead><tbody>{}</tbody></table></div>\n",
        escape(title),
        escape(headings[0]),
        escape(headings[1]),
        body
    )
}

/// Escape a value for safe insertion into HTML text or attributes.
fn escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
    output
}

fn response_code_name(code: u16) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "UNKNOWN",
    }
}

fn query_type_name(kind: u16) -> &'static str {
    match kind {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        41 => "OPT",
        65 => "HTTPS",
        _ => "UNKNOWN",
    }
}

const STYLE: &str = "<style>\n\
:root{color-scheme:dark;--bg:#12151c;--panel:#1c212b;--line:#2c3444;--fg:#e6e9ef;--muted:#8e97aa;--good:#57d38c;--bad:#ff7a7a}\n\
*{box-sizing:border-box}\n\
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}\n\
main{max-width:1000px;margin:0 auto;padding:32px 20px 48px}\n\
h1{font-size:1.6rem;margin:0}h2{font-size:1.05rem;margin:0 0 12px;color:var(--muted)}\n\
header{margin-bottom:24px}.subtitle{margin:4px 0 0;color:var(--muted)}\n\
.muted{color:var(--muted);font-weight:400}\n\
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}\n\
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}\n\
.card .label{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}\n\
.card .value{font-size:1.5rem;font-weight:600;margin-top:4px;overflow-wrap:anywhere}\n\
.card.ok .value{color:var(--good)}.card.good .value{color:var(--good)}.card.bad .value{color:var(--bad)}\n\
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}\n\
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}\n\
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 4px;border-bottom:1px solid var(--line)}\n\
th{color:var(--muted);font-size:.8rem;text-transform:uppercase}.num{text-align:right;font-variant-numeric:tabular-nums}\n\
.empty{color:var(--muted);text-align:center;padding:16px 4px}\n\
.notice{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--good);border-radius:8px;padding:12px 16px;color:var(--muted)}\n\
code{background:var(--line);padding:1px 5px;border-radius:4px}\n\
footer{text-align:center;color:var(--muted);font-size:.8rem;padding:0 20px 24px}\n\
</style>\n";

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn data() -> PageData<'static> {
        let mut stats = StatsSnapshot::default();
        stats.total_queries = 3;
        stats.response_codes.insert(3, 1);
        stats.query_types.insert(28, 2);
        stats.transports.insert("UDP".to_owned(), 3);
        stats.top_domains.push(("example.com".to_owned(), 2));
        PageData {
            instance: "NanoDNS",
            version: "0.1.0",
            uptime_secs: 42,
            resolver_mode: "Forward",
            stats: Some(stats),
        }
    }

    #[test]
    fn renders_dashboard_with_stats() {
        let html = render(&data());
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("NanoDNS"));
        assert!(html.contains(">42 s<"));
        assert!(html.contains("NOERROR") || html.contains("NXDOMAIN"));
        assert!(html.contains("example.com"));
        assert!(html.contains("AAAA"));
    }

    #[test]
    fn renders_notice_without_stats() {
        let mut page = data();
        page.stats = None;
        let html = render(&page);
        assert!(html.contains("Statistics are disabled"));
        assert!(!html.contains("Top domains"));
    }

    #[test]
    fn escapes_dynamic_values() {
        let mut page = data();
        page.instance = "<script>alert('x')</script>";
        page.stats.as_mut().expect("stats").top_domains.clear();
        page.stats
            .as_mut()
            .expect("stats")
            .top_domains
            .push(("<img src=x>".to_owned(), 1));
        let html = render(&page);
        assert!(!html.contains("<script>"));
        assert!(!html.contains("<img src=x>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;img src=x&gt;"));
    }

    #[test]
    fn empty_tables_use_placeholder() {
        let html = table(
            "Codes",
            &["Code", "Count"],
            BTreeMap::<u16, u64>::new()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v)),
        );
        assert!(html.contains("No data yet"));
    }
}
