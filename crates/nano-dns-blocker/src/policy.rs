//! Domain-based blocking policy with optional decision cache.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use nano_dns_core::config::{BlockerConfig, ClientConfig, PolicyCacheConfig};
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::{Decision, DnsQuery, QueryContext};
use nano_dns_core::traits::Policy;
use tracing::debug;

use crate::error::BlockerError;
use crate::list::{DomainSet, normalize, parse_list};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DecisionKey {
    name: String,
    client: Option<String>,
}

#[derive(Debug, Default)]
struct DecisionCache {
    entries: HashMap<DecisionKey, (Decision, u64)>,
    tick: u64,
    max_entries: usize,
}

impl DecisionCache {
    fn get(&mut self, key: &DecisionKey) -> Option<Decision> {
        let entry = self.entries.get_mut(key)?;
        self.tick += 1;
        entry.1 = self.tick;
        Some(entry.0)
    }

    fn put(&mut self, key: DecisionKey, decision: Decision) {
        if self.entries.contains_key(&key) {
            return;
        }
        self.tick += 1;
        self.entries.insert(key, (decision, self.tick));
        while self.entries.len() > self.max_entries {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, (_, tick))| *tick)
                .map(|(key, _)| key.clone());
            match victim {
                Some(key) => {
                    self.entries.remove(&key);
                }
                None => break,
            }
        }
    }
}

/// Blocking policy built from global rules, per-client rules and local lists.
pub struct DomainBlocker {
    allow: DomainSet,
    deny: DomainSet,
    clients: HashMap<String, (DomainSet, DomainSet)>,
    cache: Option<Mutex<DecisionCache>>,
}

impl DomainBlocker {
    /// Load all configured rules and lists.
    ///
    /// Remote list sources are rejected: this phase only reads local files and
    /// performs no network access or background refresh.
    pub fn new(
        config: &BlockerConfig,
        clients: &[ClientConfig],
        cache_config: Option<&PolicyCacheConfig>,
    ) -> CoreResult<Self> {
        let mut allow = DomainSet::default();
        let mut deny = DomainSet::default();
        for domain in &config.allowlist {
            allow.insert(domain);
        }
        for domain in &config.denylist {
            deny.insert(domain);
        }

        for source in &config.lists {
            if !source.enabled || !config.categories.contains(&source.category) {
                continue;
            }
            if source.source.contains("://") {
                return Err(BlockerError::RemoteSource(source.source.clone()).into());
            }
            let configured = Path::new(&source.source);
            let path = if configured.is_absolute() {
                configured.to_path_buf()
            } else {
                config.lists_dir.join(configured)
            };
            let bytes = fs::read(&path).map_err(|source| BlockerError::Io {
                path: path.clone(),
                source,
            })?;
            let text = String::from_utf8(bytes).map_err(|source| BlockerError::Encoding {
                path: path.clone(),
                source,
            })?;
            for domain in parse_list(&text) {
                deny.insert(&domain);
            }
            debug!(list = %source.id, path = %path.display(), "block list loaded");
        }

        let mut client_rules = HashMap::new();
        for client in clients {
            let mut client_allow = DomainSet::default();
            let mut client_deny = DomainSet::default();
            for domain in &client.allowlist {
                client_allow.insert(domain);
            }
            for domain in &client.denylist {
                client_deny.insert(domain);
            }
            client_rules.insert(client.id.clone(), (client_allow, client_deny));
        }

        let cache = cache_config.map(|config| {
            Mutex::new(DecisionCache {
                max_entries: config.max_entries,
                ..DecisionCache::default()
            })
        });

        Ok(Self {
            allow,
            deny,
            clients: client_rules,
            cache,
        })
    }

    /// Number of cached decisions, for diagnostics and tests.
    pub fn cached_decisions(&self) -> usize {
        self.cache.as_ref().map_or(0, |cache| {
            cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entries
                .len()
        })
    }

    fn decide_uncached(&self, name: &str, context: &QueryContext) -> Decision {
        if self.allow.matches(name) {
            return Decision::Allow;
        }
        if let Some((client_allow, client_deny)) = context
            .client
            .id
            .as_deref()
            .and_then(|id| self.clients.get(id))
        {
            if client_allow.matches(name) {
                return Decision::Allow;
            }
            if client_deny.matches(name) {
                return Decision::Block;
            }
        }
        if self.deny.matches(name) {
            return Decision::Block;
        }
        Decision::Allow
    }
}

impl Policy for DomainBlocker {
    type Query = DnsQuery;

    fn decide(&self, query: &DnsQuery, context: &QueryContext) -> Decision {
        let name = normalize(&query.name);
        let key = DecisionKey {
            name: name.clone(),
            client: context.client.id.clone(),
        };

        if let Some(cache) = &self.cache {
            let mut cache = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(decision) = cache.get(&key) {
                return decision;
            }
        }

        let decision = self.decide_uncached(&name, context);
        if let Some(cache) = &self.cache {
            let mut cache = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.put(key, decision);
        }
        decision
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    use nano_dns_core::config::{BlockCategory, ListSource};
    use nano_dns_core::model::{ClientIdentity, Transport};

    use super::*;

    fn config() -> BlockerConfig {
        BlockerConfig {
            enabled: true,
            ..BlockerConfig::default()
        }
    }

    fn query(name: &str) -> DnsQuery {
        DnsQuery {
            id: 1,
            name: name.to_owned(),
            query_type: 1,
            query_class: 1,
            bytes: Vec::new(),
        }
    }

    fn context(client_id: Option<&str>) -> QueryContext {
        let mut context = QueryContext::new(
            ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Transport::Udp,
        );
        context.client.id = client_id.map(str::to_owned);
        context
    }

    fn client(id: &str, allow: &[&str], deny: &[&str]) -> ClientConfig {
        ClientConfig {
            id: id.to_owned(),
            name: id.to_owned(),
            networks: Vec::new(),
            allowlist: allow.iter().map(|domain| (*domain).to_owned()).collect(),
            denylist: deny.iter().map(|domain| (*domain).to_owned()).collect(),
        }
    }

    #[test]
    fn global_denylist_blocks_domain_and_subdomains() {
        let mut config = config();
        config.denylist = vec!["ads.example.com.".to_owned()];
        let blocker = DomainBlocker::new(&config, &[], None).expect("blocker must build");

        assert_eq!(
            blocker.decide(&query("ads.example.com."), &context(None)),
            Decision::Block
        );
        assert_eq!(
            blocker.decide(&query("www.ads.example.com"), &context(None)),
            Decision::Block
        );
        assert_eq!(
            blocker.decide(&query("example.com"), &context(None)),
            Decision::Allow
        );
    }

    #[test]
    fn allowlist_overrides_denylist() {
        let mut config = config();
        config.denylist = vec!["example.com".to_owned()];
        config.allowlist = vec!["www.example.com".to_owned()];
        let blocker = DomainBlocker::new(&config, &[], None).expect("blocker must build");

        assert_eq!(
            blocker.decide(&query("www.example.com"), &context(None)),
            Decision::Allow
        );
        assert_eq!(
            blocker.decide(&query("mail.example.com"), &context(None)),
            Decision::Block
        );
    }

    #[test]
    fn client_rules_are_applied_by_client_id() {
        let mut config = config();
        config.denylist = vec!["ads.example.com".to_owned()];
        let clients = vec![
            client("phone", &["ads.example.com"], &[]),
            client("tv", &[], &["video.example.net"]),
        ];
        let blocker = DomainBlocker::new(&config, &clients, None).expect("blocker must build");

        assert_eq!(
            blocker.decide(&query("ads.example.com"), &context(Some("phone"))),
            Decision::Allow
        );
        assert_eq!(
            blocker.decide(&query("ads.example.com"), &context(Some("tv"))),
            Decision::Block
        );
        assert_eq!(
            blocker.decide(&query("video.example.net"), &context(Some("tv"))),
            Decision::Block
        );
        assert_eq!(
            blocker.decide(&query("video.example.net"), &context(None)),
            Decision::Allow
        );
    }

    #[test]
    fn local_list_file_is_loaded_only_for_enabled_categories() {
        let dir = std::env::temp_dir().join(format!(
            "nanodns-blocker-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("list.txt");
        fs::write(&file, "||tracker.example.org^\n").expect("list file");

        let mut config = config();
        config.lists_dir = dir.clone();
        config.lists = vec![ListSource {
            id: "test".to_owned(),
            name: "Test".to_owned(),
            category: BlockCategory::Advertising,
            source: "list.txt".to_owned(),
            enabled: true,
            refresh_secs: 0,
        }];
        let blocker = DomainBlocker::new(&config, &[], None).expect("blocker must build");
        assert_eq!(
            blocker.decide(&query("tracker.example.org"), &context(None)),
            Decision::Block
        );

        config.categories = vec![BlockCategory::Malware];
        let blocker = DomainBlocker::new(&config, &[], None).expect("blocker must build");
        assert_eq!(
            blocker.decide(&query("tracker.example.org"), &context(None)),
            Decision::Allow
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_sources_are_rejected() {
        let mut config = config();
        config.categories.push(BlockCategory::Custom);
        config.lists = vec![ListSource {
            id: "remote".to_owned(),
            name: "Remote".to_owned(),
            category: BlockCategory::Custom,
            source: "https://example.com/list.txt".to_owned(),
            enabled: true,
            refresh_secs: 0,
        }];
        assert!(DomainBlocker::new(&config, &[], None).is_err());
    }

    #[test]
    fn missing_list_file_fails_at_startup() {
        let mut config = config();
        config.categories.push(BlockCategory::Custom);
        config.lists = vec![ListSource {
            id: "missing".to_owned(),
            name: "Missing".to_owned(),
            category: BlockCategory::Custom,
            source: "does-not-exist.txt".to_owned(),
            enabled: true,
            refresh_secs: 0,
        }];
        assert!(DomainBlocker::new(&config, &[], None).is_err());
    }

    #[test]
    fn decision_cache_is_used_and_bounded() {
        let mut config = config();
        config.denylist = vec!["ads.example.com".to_owned()];
        let cache = PolicyCacheConfig {
            enabled: true,
            max_entries: 2,
        };
        let blocker = DomainBlocker::new(&config, &[], Some(&cache)).expect("blocker must build");
        let first = query("ads.example.com");
        let second = query("other.example.net");
        let third = query("third.example.org");

        assert_eq!(blocker.decide(&first, &context(None)), Decision::Block);
        assert_eq!(blocker.decide(&first, &context(None)), Decision::Block);
        assert_eq!(blocker.cached_decisions(), 1);

        assert_eq!(blocker.decide(&second, &context(None)), Decision::Allow);
        assert_eq!(blocker.decide(&third, &context(None)), Decision::Allow);
        assert_eq!(blocker.cached_decisions(), 2);
    }
}
