//! Domain-based blocking policy with a decision cache and runtime control.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use nano_dns_core::blocker::{
    BlockListKind, BlockListStatus, BlockedDomain, BlockerControl, BlockerSnapshot,
};
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

#[derive(Debug, Default)]
struct BlockStats {
    total: u64,
    per_domain: HashMap<String, u64>,
}

/// Read lock that keeps working if a previous writer panicked.
fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Write lock that keeps working if a previous writer panicked.
fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Mutex lock that keeps working if a previous holder panicked.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Blocking policy built from global rules, per-client rules, local lists and
/// runtime changes made through [`BlockerControl`].
pub struct DomainBlocker {
    config: BlockerConfig,
    enabled: AtomicBool,
    allow: DomainSet,
    config_deny: DomainSet,
    file_deny: RwLock<DomainSet>,
    custom_allow: RwLock<DomainSet>,
    custom_deny: RwLock<DomainSet>,
    clients: HashMap<String, (DomainSet, DomainSet)>,
    cache: Option<Mutex<DecisionCache>>,
    stats: RwLock<BlockStats>,
    lists: RwLock<Vec<BlockListStatus>>,
}

impl DomainBlocker {
    /// Load all configured rules and lists.
    ///
    /// Remote list sources are rejected: this implementation only reads local
    /// files and performs no network access or background refresh. The
    /// configured `enabled` value becomes the initial runtime state.
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

        let (file_deny, lists) = load_lists(config)?;

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
            config: config.clone(),
            enabled: AtomicBool::new(config.enabled),
            allow,
            config_deny: deny,
            file_deny: RwLock::new(file_deny),
            custom_allow: RwLock::new(DomainSet::default()),
            custom_deny: RwLock::new(DomainSet::default()),
            clients: client_rules,
            cache,
            stats: RwLock::new(BlockStats::default()),
            lists: RwLock::new(lists),
        })
    }

    /// Number of cached decisions, for diagnostics and tests.
    pub fn cached_decisions(&self) -> usize {
        self.cache
            .as_ref()
            .map_or(0, |cache| lock(cache).entries.len())
    }

    fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            lock(cache).entries.clear();
        }
    }

    fn record_block(&self, name: &str) {
        let mut stats = write(&self.stats);
        stats.total += 1;
        *stats.per_domain.entry(name.to_owned()).or_default() += 1;
    }

    fn decide_uncached(&self, name: &str, context: &QueryContext) -> Decision {
        if self.allow.matches(name) || read(&self.custom_allow).matches(name) {
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
        if self.config_deny.matches(name)
            || read(&self.file_deny).matches(name)
            || read(&self.custom_deny).matches(name)
        {
            return Decision::Block;
        }
        Decision::Allow
    }
}

/// Whether a recorded query domain equals an entry or one of its subdomains.
fn domain_matches(entry: &str, name: &str) -> bool {
    let entry = normalize(entry);
    let name = normalize(name);
    name == entry
        || name
            .strip_suffix(entry.as_str())
            .is_some_and(|parent| parent.ends_with('.'))
}

/// Read one set of configured local list files.
fn load_lists(config: &BlockerConfig) -> CoreResult<(DomainSet, Vec<BlockListStatus>)> {
    let mut domains = DomainSet::default();
    let mut statuses = Vec::with_capacity(config.lists.len());

    for source in &config.lists {
        let active = source.enabled && config.categories.contains(&source.category);
        let status = BlockListStatus {
            id: source.id.clone(),
            name: source.name.clone(),
            category: format!("{:?}", source.category),
            source: source.source.clone(),
            enabled: active,
            entries: 0,
        };
        if !active {
            statuses.push(status);
            continue;
        }
        if source.source.contains("://") {
            return Err(BlockerError::RemoteSource(source.source.clone()).into());
        }
        let configured = Path::new(&source.source);
        let path: PathBuf = if configured.is_absolute() {
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

        let mut list = DomainSet::default();
        for domain in parse_list(&text) {
            list.insert(&domain);
        }
        let mut status = status;
        status.entries = list.len();
        for domain in list.entries() {
            domains.insert(domain);
        }
        debug!(list = %source.id, path = %path.display(), "block list loaded");
        statuses.push(status);
    }

    Ok((domains, statuses))
}

impl Policy for DomainBlocker {
    type Query = DnsQuery;

    fn decide(&self, query: &DnsQuery, context: &QueryContext) -> Decision {
        if !self.enabled.load(Ordering::Relaxed) {
            return Decision::Allow;
        }

        let name = normalize(&query.name);
        let key = DecisionKey {
            name: name.clone(),
            client: context.client.id.clone(),
        };

        let cached = self.cache.as_ref().and_then(|cache| lock(cache).get(&key));
        if let Some(decision) = cached {
            if decision == Decision::Block {
                self.record_block(&name);
            }
            return decision;
        }

        let decision = self.decide_uncached(&name, context);
        if decision == Decision::Block {
            self.record_block(&name);
        }
        if let Some(cache) = &self.cache {
            lock(cache).put(key, decision);
        }
        decision
    }
}

impl BlockerControl for DomainBlocker {
    fn snapshot(&self) -> BlockerSnapshot {
        let stats = read(&self.stats);
        let mut top_blocked: Vec<(String, u64)> = stats
            .per_domain
            .iter()
            .map(|(name, count)| (name.clone(), *count))
            .collect();
        top_blocked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        top_blocked.truncate(10);

        let custom_allow = read(&self.custom_allow);
        let custom_deny = read(&self.custom_deny);
        let mut domains = Vec::with_capacity(custom_allow.len() + custom_deny.len());
        for (set, kind) in [
            (&*custom_allow, BlockListKind::Allow),
            (&*custom_deny, BlockListKind::Deny),
        ] {
            for domain in set.entries() {
                let hits = stats
                    .per_domain
                    .iter()
                    .filter(|(name, _)| domain_matches(domain, name))
                    .map(|(_, count)| *count)
                    .sum();
                domains.push(BlockedDomain {
                    domain: domain.to_owned(),
                    kind,
                    hits,
                });
            }
        }
        domains.sort_by(|left, right| {
            right
                .hits
                .cmp(&left.hits)
                .then_with(|| left.domain.cmp(&right.domain))
        });

        BlockerSnapshot {
            enabled: self.enabled.load(Ordering::Relaxed),
            total_blocked: stats.total,
            domains,
            top_blocked,
            lists: read(&self.lists).clone(),
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.clear_cache();
    }

    fn add_domains(&self, kind: BlockListKind, text: &str) -> CoreResult<usize> {
        let set = match kind {
            BlockListKind::Allow => &self.custom_allow,
            BlockListKind::Deny => &self.custom_deny,
        };
        let mut set = write(set);
        let mut added = 0usize;
        for domain in parse_list(text) {
            if !set.contains(&domain) {
                set.insert(&domain);
                added += 1;
            }
        }
        drop(set);
        if added > 0 {
            self.clear_cache();
        }
        Ok(added)
    }

    fn remove_domain(&self, kind: BlockListKind, domain: &str) -> CoreResult<bool> {
        let set = match kind {
            BlockListKind::Allow => &self.custom_allow,
            BlockListKind::Deny => &self.custom_deny,
        };
        let removed = write(set).remove(domain);
        if removed {
            self.clear_cache();
        }
        Ok(removed)
    }

    fn clear_domains(&self, kind: BlockListKind) -> usize {
        let set = match kind {
            BlockListKind::Allow => &self.custom_allow,
            BlockListKind::Deny => &self.custom_deny,
        };
        let mut set = write(set);
        let removed = set.len();
        *set = DomainSet::default();
        drop(set);
        if removed > 0 {
            self.clear_cache();
        }
        removed
    }

    fn reload_lists(&self) -> CoreResult<usize> {
        let (domains, statuses) = load_lists(&self.config)?;
        let total = domains.len();
        *write(&self.file_deny) = domains;
        *write(&self.lists) = statuses;
        self.clear_cache();
        Ok(total)
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

    #[test]
    fn runtime_toggle_disables_and_reenables_filtering() {
        let mut config = config();
        config.denylist = vec!["ads.example.com".to_owned()];
        let blocker = DomainBlocker::new(&config, &[], None).expect("blocker must build");
        let control: &dyn BlockerControl = &blocker;

        assert_eq!(
            blocker.decide(&query("ads.example.com"), &context(None)),
            Decision::Block
        );
        control.set_enabled(false);
        assert!(!control.is_enabled());
        assert_eq!(
            blocker.decide(&query("ads.example.com"), &context(None)),
            Decision::Allow
        );
        control.set_enabled(true);
        assert_eq!(
            blocker.decide(&query("ads.example.com"), &context(None)),
            Decision::Block
        );
    }

    #[test]
    fn runtime_domains_can_be_added_removed_and_cleared() {
        let blocker = DomainBlocker::new(&config(), &[], None).expect("blocker must build");
        let control: &dyn BlockerControl = &blocker;

        assert_eq!(
            control
                .add_domains(BlockListKind::Deny, "ads.example.net\n||track.example.org^")
                .expect("add"),
            2
        );
        assert_eq!(
            blocker.decide(&query("www.ads.example.net"), &context(None)),
            Decision::Block
        );
        assert_eq!(
            blocker.decide(&query("track.example.org"), &context(None)),
            Decision::Block
        );

        assert!(
            control
                .remove_domain(BlockListKind::Deny, "ADS.EXAMPLE.NET.")
                .expect("remove")
        );
        assert_eq!(
            blocker.decide(&query("www.ads.example.net"), &context(None)),
            Decision::Allow
        );
        assert_eq!(control.clear_domains(BlockListKind::Deny), 1);
        assert_eq!(
            blocker.decide(&query("track.example.org"), &context(None)),
            Decision::Allow
        );
    }

    #[test]
    fn runtime_allow_rule_overrides_configured_denylist() {
        let mut config = config();
        config.denylist = vec!["example.com".to_owned()];
        let blocker = DomainBlocker::new(&config, &[], None).expect("blocker must build");
        let control: &dyn BlockerControl = &blocker;

        control
            .add_domains(BlockListKind::Allow, "www.example.com")
            .expect("allow rule");
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
    fn runtime_changes_invalidate_cached_decisions() {
        let blocker = DomainBlocker::new(
            &config(),
            &[],
            Some(&PolicyCacheConfig {
                enabled: true,
                max_entries: 8,
            }),
        )
        .expect("blocker must build");
        let control: &dyn BlockerControl = &blocker;
        let lookup = query("ads.example.net");

        assert_eq!(blocker.decide(&lookup, &context(None)), Decision::Allow);
        control
            .add_domains(BlockListKind::Deny, "ads.example.net")
            .expect("deny rule");
        assert_eq!(blocker.cached_decisions(), 0);
        assert_eq!(blocker.decide(&lookup, &context(None)), Decision::Block);
    }

    #[test]
    fn reload_lists_picks_up_file_changes() {
        let dir = std::env::temp_dir().join(format!(
            "nanodns-reload-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("list.txt");
        fs::write(&file, "first.example.net\n").expect("list file");

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
        let control: &dyn BlockerControl = &blocker;

        assert_eq!(
            blocker.decide(&query("first.example.net"), &context(None)),
            Decision::Block
        );
        assert_eq!(
            blocker.decide(&query("second.example.net"), &context(None)),
            Decision::Allow
        );

        fs::write(&file, "second.example.net\nthird.example.net\n").expect("updated list");
        assert_eq!(control.reload_lists().expect("reload"), 2);
        assert_eq!(
            blocker.decide(&query("first.example.net"), &context(None)),
            Decision::Allow
        );
        assert_eq!(
            blocker.decide(&query("second.example.net"), &context(None)),
            Decision::Block
        );
        assert_eq!(control.snapshot().lists[0].entries, 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_reports_block_counters() {
        let mut config = config();
        config.denylist = vec!["ads.example.com".to_owned()];
        let blocker = DomainBlocker::new(&config, &[], None).expect("blocker must build");
        let control: &dyn BlockerControl = &blocker;

        let _ = blocker.decide(&query("ads.example.com"), &context(None));
        let _ = blocker.decide(&query("www.ads.example.com"), &context(None));
        let snapshot = control.snapshot();

        assert!(snapshot.enabled);
        assert_eq!(snapshot.total_blocked, 2);
        assert_eq!(snapshot.top_blocked[0].0, "ads.example.com");
        assert_eq!(snapshot.top_blocked[0].1, 1);
    }
}
