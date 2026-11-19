//! Domain normalization, suffix matching and list file parsing.

/// Normalize a domain for comparison: lower case, no trailing dot, no wildcard
/// or leading-dot marker.
pub(crate) fn normalize(domain: &str) -> String {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let domain = domain.strip_prefix("*.").unwrap_or(&domain);
    let domain = domain.strip_prefix('.').unwrap_or(domain);
    domain.to_owned()
}

/// A set of normalized domains matched exactly or as a parent suffix.
#[derive(Debug, Clone, Default)]
pub(crate) struct DomainSet {
    domains: Vec<String>,
}

impl DomainSet {
    /// Add a domain to the set.
    pub(crate) fn insert(&mut self, domain: &str) {
        let domain = normalize(domain);
        if !domain.is_empty() && !self.domains.contains(&domain) {
            self.domains.push(domain);
        }
    }

    /// Whether an exact normalized domain is present.
    pub(crate) fn contains(&self, domain: &str) -> bool {
        let domain = normalize(domain);
        self.domains.iter().any(|entry| entry == &domain)
    }

    /// Remove a domain. Returns `true` when an entry was removed.
    pub(crate) fn remove(&mut self, domain: &str) -> bool {
        let domain = normalize(domain);
        let before = self.domains.len();
        self.domains.retain(|entry| entry != &domain);
        self.domains.len() != before
    }

    /// Return every entry in insertion order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = &str> {
        self.domains.iter().map(String::as_str)
    }

    /// Number of entries in the set.
    pub(crate) fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether `name` is this domain or a subdomain of an entry.
    pub(crate) fn matches(&self, name: &str) -> bool {
        let name = normalize(name);
        self.domains.iter().any(|domain| {
            name == *domain
                || name
                    .strip_suffix(domain.as_str())
                    .is_some_and(|parent| parent.ends_with('.'))
        })
    }
}

/// Extract normalized domains from a block list.
///
/// Supports plain domains, `.`/`*.` prefixes, adblock `||domain^` syntax and
/// hosts-file rows such as `0.0.0.0 ads.example.com`. Comments and adblock
/// exception lines are ignored.
pub(crate) fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with('!')
                || line.starts_with('[')
            {
                return None;
            }
            let line = line.strip_prefix("||").unwrap_or(line);
            let line = line.strip_suffix('^').unwrap_or(line);
            let token = if line.chars().any(char::is_whitespace) {
                let mut parts = line.split_whitespace();
                let first = parts.next()?;
                if first.parse::<std::net::IpAddr>().is_ok() {
                    parts.next()?
                } else {
                    first
                }
            } else {
                line
            };
            let domain = normalize(token);
            if domain.is_empty() || !domain.contains('.') || domain.contains("://") {
                return None;
            }
            Some(domain)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_is_case_insensitive_and_removes_markers() {
        assert_eq!(normalize("Ads.Example.COM."), "ads.example.com");
        assert_eq!(normalize("*.Example.com"), "example.com");
        assert_eq!(normalize(".example.com"), "example.com");
    }

    #[test]
    fn suffix_matching_does_not_match_unrelated_names() {
        let mut set = DomainSet::default();
        set.insert("example.com");
        assert!(set.matches("example.com"));
        assert!(set.matches("www.example.com"));
        assert!(set.matches("a.b.example.com."));
        assert!(!set.matches("notexample.com"));
        assert!(!set.matches("example.org"));
    }

    #[test]
    fn common_list_formats_are_parsed() {
        let text = "\
# header
||ads.example.com^
*.tracker.example.net
0.0.0.0 malware.example.org
127.0.0.1 phishing.example.org # comment
!exception.example.com
localhost
";
        let domains = parse_list(text);
        assert!(domains.contains(&"ads.example.com".to_owned()));
        assert!(domains.contains(&"tracker.example.net".to_owned()));
        assert!(domains.contains(&"malware.example.org".to_owned()));
        assert!(domains.contains(&"phishing.example.org".to_owned()));
        assert!(!domains.iter().any(|domain| domain == "localhost"));
        assert!(!domains.iter().any(|domain| domain.contains("exception")));
    }

    #[test]
    fn domain_set_supports_contains_remove_entries_and_len() {
        let mut set = DomainSet::default();
        set.insert("Ads.Example.COM.");
        set.insert("ads.example.com");
        set.insert("");
        set.insert("localhost");

        assert_eq!(set.len(), 2);
        assert_eq!(
            set.entries().collect::<Vec<_>>(),
            vec!["ads.example.com", "localhost"]
        );
        assert!(set.contains("ADS.EXAMPLE.COM."));
        assert!(set.remove("*.ads.example.com"));
        assert!(!set.remove("ads.example.com"));
        assert!(set.contains("localhost"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn parse_list_accepts_ipv6_hosts_and_inline_comments() {
        let domains = parse_list("::1 tracker.example.net # local\n0.0.0.0  ads.example.com\n");
        assert_eq!(
            domains,
            vec![
                "tracker.example.net".to_owned(),
                "ads.example.com".to_owned()
            ]
        );
    }

    #[test]
    fn parse_list_ignores_urls_and_non_domain_tokens() {
        let domains = parse_list(
            "https://tracker.example.net\n\
             not-a-domain\n\
             \n\
             [Adblock Plus 2.0]\n",
        );
        assert!(domains.is_empty());
    }

    #[test]
    fn parse_list_normalizes_wildcard_adblock_and_leading_dot_forms() {
        let domains = parse_list("||ADS.Example.COM^\n*.Track.Example.NET\n.Lead.Example.ORG");
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"ads.example.com".to_owned()));
        assert!(domains.contains(&"track.example.net".to_owned()));
        assert!(domains.contains(&"lead.example.org".to_owned()));
    }
}
