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
            if domain.is_empty() || !domain.contains('.') {
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
}
