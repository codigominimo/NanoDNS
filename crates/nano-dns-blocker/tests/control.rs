//! Exhaustive runtime-control tests for the blocking policy.
//!
//! These tests use only the public interfaces (`Policy` and `BlockerControl`)
//! and never touch the network or Hickory.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use nano_dns_blocker::DomainBlocker;
use nano_dns_core::blocker::{BlockListKind, BlockerControl};
use nano_dns_core::config::{
    BlockCategory, BlockerConfig, ClientConfig, ListSource, PolicyCacheConfig,
};
use nano_dns_core::error::Error;
use nano_dns_core::model::{ClientIdentity, Decision, DnsQuery, QueryContext, Transport};
use nano_dns_core::traits::Policy;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let dir = std::env::temp_dir().join(format!(
        "nanodns-{label}-{}-{nanos}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("temporary directory");
    dir
}

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
        allowlist: allow.iter().map(|name| (*name).to_owned()).collect(),
        denylist: deny.iter().map(|name| (*name).to_owned()).collect(),
    }
}

fn source(id: &str, source: &str, category: BlockCategory, enabled: bool) -> ListSource {
    ListSource {
        id: id.to_owned(),
        name: id.to_owned(),
        category,
        source: source.to_owned(),
        enabled,
        refresh_secs: 0,
    }
}

fn blocker(
    config: &BlockerConfig,
    clients: &[ClientConfig],
    cache: Option<&PolicyCacheConfig>,
) -> DomainBlocker {
    DomainBlocker::new(config, clients, cache).expect("blocker must build")
}

fn add(control: &dyn BlockerControl, kind: BlockListKind, text: &str) -> usize {
    control.add_domains(kind, text).expect("add domains")
}

fn remove(control: &dyn BlockerControl, kind: BlockListKind, domain: &str) -> bool {
    control.remove_domain(kind, domain).expect("remove domain")
}

fn reload(control: &dyn BlockerControl) -> usize {
    control.reload_lists().expect("reload lists")
}

#[test]
fn blocker_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DomainBlocker>();
}

#[test]
fn initial_enabled_flag_controls_first_decision() {
    let mut config = config();
    config.denylist = vec!["ads.example.com".to_owned()];
    config.enabled = false;
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    assert!(!control.is_enabled());
    assert!(!control.snapshot().enabled);
    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(None)),
        Decision::Allow
    );

    control.set_enabled(true);
    assert!(control.is_enabled());
    assert!(control.snapshot().enabled);
    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(None)),
        Decision::Block
    );
}

#[test]
fn toggling_clears_cached_allow_and_block_decisions() {
    let mut config = config();
    config.denylist = vec!["ads.example.com".to_owned()];
    let cache = PolicyCacheConfig {
        enabled: true,
        max_entries: 8,
    };
    let blocker = blocker(&config, &[], Some(&cache));
    let control: &dyn BlockerControl = &blocker;
    let lookup = query("ads.example.com");

    assert_eq!(blocker.decide(&lookup, &context(None)), Decision::Block);
    assert_eq!(blocker.cached_decisions(), 1);

    control.set_enabled(false);
    assert_eq!(blocker.cached_decisions(), 0);
    assert_eq!(blocker.decide(&lookup, &context(None)), Decision::Allow);

    control.set_enabled(true);
    assert_eq!(blocker.cached_decisions(), 0);
    assert_eq!(blocker.decide(&lookup, &context(None)), Decision::Block);
}

#[test]
fn add_domains_accepts_every_supported_list_format() {
    let blocker = blocker(&config(), &[], None);
    let control: &dyn BlockerControl = &blocker;
    let text = "\
# comment
! exception.example.com
[Adblock Plus 2.0]
||ADS.Example.COM^
*.Track.Example.NET
0.0.0.0 malware.example.org
::1 phishing.example.org
https://ignored.example.net
localhost
";

    assert_eq!(add(control, BlockListKind::Deny, text), 4);
    for name in [
        "ads.example.com",
        "www.ads.example.com",
        "track.example.net",
        "malware.example.org",
        "phishing.example.org",
    ] {
        assert_eq!(
            blocker.decide(&query(name), &context(None)),
            Decision::Block,
            "{name} must be blocked"
        );
    }
    assert_eq!(
        blocker.decide(&query("ignored.example.net"), &context(None)),
        Decision::Allow
    );
}

#[test]
fn add_domains_ignores_empty_duplicate_and_invalid_entries() {
    let blocker = blocker(&config(), &[], None);
    let control: &dyn BlockerControl = &blocker;

    assert_eq!(add(control, BlockListKind::Deny, ""), 0);
    assert_eq!(add(control, BlockListKind::Deny, "# only comments\n\n"), 0);
    assert_eq!(
        add(
            control,
            BlockListKind::Deny,
            "ADS.Example.COM.\nads.example.com\n||ads.example.com^\nlocalhost"
        ),
        1
    );
    assert_eq!(control.snapshot().domains.len(), 1);
}

#[test]
fn remove_domain_normalizes_case_wildcards_and_trailing_dot() {
    let blocker = blocker(&config(), &[], None);
    let control: &dyn BlockerControl = &blocker;
    assert_eq!(add(control, BlockListKind::Deny, "ads.example.net"), 1);

    assert_eq!(
        remove(control, BlockListKind::Deny, "ADS.EXAMPLE.NET."),
        true
    );
    assert_eq!(
        remove(control, BlockListKind::Deny, "*.ads.example.net"),
        false
    );
    assert_eq!(
        blocker.decide(&query("www.ads.example.net"), &context(None)),
        Decision::Allow
    );
}

#[test]
fn remove_domain_does_not_touch_configured_rules() {
    let mut config = config();
    config.denylist = vec!["ads.example.com".to_owned()];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    assert_eq!(
        remove(control, BlockListKind::Deny, "ads.example.com"),
        false
    );
    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(None)),
        Decision::Block
    );
}

#[test]
fn remove_domain_does_not_touch_loaded_list_rules() {
    let dir = temp_dir("list-remove");
    let file = dir.join("ads.txt");
    fs::write(&file, "ads.example.net\n").expect("list file");
    let mut config = config();
    config.lists_dir = dir.clone();
    config.lists = vec![source("ads", "ads.txt", BlockCategory::Advertising, true)];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    assert_eq!(
        remove(control, BlockListKind::Deny, "ads.example.net"),
        false
    );
    assert_eq!(
        blocker.decide(&query("ads.example.net"), &context(None)),
        Decision::Block
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn clear_domains_only_affects_the_requested_kind() {
    let mut config = config();
    config.denylist = vec!["example.com".to_owned()];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    assert_eq!(add(control, BlockListKind::Allow, "www.example.com"), 1);
    assert_eq!(add(control, BlockListKind::Deny, "ads.example.net"), 1);
    assert_eq!(control.clear_domains(BlockListKind::Deny), 1);

    assert_eq!(
        blocker.decide(&query("ads.example.net"), &context(None)),
        Decision::Allow
    );
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
fn clear_domains_is_idempotent() {
    let blocker = blocker(&config(), &[], None);
    let control: &dyn BlockerControl = &blocker;
    assert_eq!(
        add(
            control,
            BlockListKind::Deny,
            "one.example.net\ntwo.example.net"
        ),
        2
    );

    assert_eq!(control.clear_domains(BlockListKind::Deny), 2);
    assert_eq!(control.clear_domains(BlockListKind::Deny), 0);
    assert_eq!(control.clear_domains(BlockListKind::Allow), 0);
}

#[test]
fn runtime_allow_overrides_client_deny_rules() {
    let clients = vec![client("tv", &[], &["ads.example.com"])];
    let blocker = blocker(&config(), &clients, None);
    let control: &dyn BlockerControl = &blocker;

    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(Some("tv"))),
        Decision::Block
    );
    assert_eq!(add(control, BlockListKind::Allow, "ads.example.com"), 1);
    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(Some("tv"))),
        Decision::Allow
    );
}

#[test]
fn client_allow_overrides_runtime_deny_rules() {
    let clients = vec![client("phone", &["ads.example.com"], &[])];
    let blocker = blocker(&config(), &clients, None);
    let control: &dyn BlockerControl = &blocker;
    assert_eq!(add(control, BlockListKind::Deny, "ads.example.com"), 1);

    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(Some("phone"))),
        Decision::Allow
    );
    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(None)),
        Decision::Block
    );
}

#[test]
fn decision_cache_is_separate_for_each_client() {
    let mut config = config();
    config.denylist = vec!["ads.example.com".to_owned()];
    let clients = vec![client("phone", &["ads.example.com"], &[])];
    let cache = PolicyCacheConfig {
        enabled: true,
        max_entries: 8,
    };
    let blocker = blocker(&config, &clients, Some(&cache));

    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(Some("phone"))),
        Decision::Allow
    );
    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(Some("tv"))),
        Decision::Block
    );
    assert_eq!(blocker.cached_decisions(), 2);
}

#[test]
fn disabling_filtering_does_not_record_blocks() {
    let mut config = config();
    config.denylist = vec!["ads.example.com".to_owned()];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    control.set_enabled(false);
    let _ = blocker.decide(&query("ads.example.com"), &context(None));
    assert_eq!(control.snapshot().total_blocked, 0);

    control.set_enabled(true);
    let _ = blocker.decide(&query("ads.example.com"), &context(None));
    assert_eq!(control.snapshot().total_blocked, 1);
}

#[test]
fn allowed_queries_do_not_change_block_counters() {
    let blocker = blocker(&config(), &[], None);
    let control: &dyn BlockerControl = &blocker;
    for name in ["example.com", "www.example.net", "mail.example.org"] {
        assert_eq!(
            blocker.decide(&query(name), &context(None)),
            Decision::Allow
        );
    }
    assert_eq!(control.snapshot().total_blocked, 0);
    assert!(control.snapshot().top_blocked.is_empty());
}

#[test]
fn cached_blocks_are_counted_on_every_query() {
    let mut config = config();
    config.denylist = vec!["ads.example.com".to_owned()];
    let cache = PolicyCacheConfig {
        enabled: true,
        max_entries: 8,
    };
    let blocker = blocker(&config, &[], Some(&cache));
    let control: &dyn BlockerControl = &blocker;
    let lookup = query("ads.example.com");

    for _ in 0..3 {
        assert_eq!(blocker.decide(&lookup, &context(None)), Decision::Block);
    }
    assert_eq!(blocker.cached_decisions(), 1);
    assert_eq!(control.snapshot().total_blocked, 3);
    assert_eq!(control.snapshot().top_blocked[0].1, 3);
}

#[test]
fn snapshot_orders_top_blocked_by_count_then_domain() {
    let mut config = config();
    config.denylist = vec![
        "b.example.com".to_owned(),
        "a.example.com".to_owned(),
        "c.example.com".to_owned(),
    ];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    let _ = blocker.decide(&query("a.example.com"), &context(None));
    let _ = blocker.decide(&query("b.example.com"), &context(None));
    let _ = blocker.decide(&query("b.example.com"), &context(None));
    let _ = blocker.decide(&query("c.example.com"), &context(None));

    let top = control.snapshot().top_blocked;
    assert_eq!(top[0], ("b.example.com".to_owned(), 2));
    assert_eq!(top[1], ("a.example.com".to_owned(), 1));
    assert_eq!(top[2], ("c.example.com".to_owned(), 1));
}

#[test]
fn snapshot_truncates_top_blocked_to_ten_entries() {
    let mut config = config();
    config.denylist = (0..12)
        .map(|index| format!("ads{index:02}.example.com"))
        .collect();
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    for domain in &config.denylist {
        let _ = blocker.decide(&query(domain), &context(None));
    }
    assert_eq!(control.snapshot().top_blocked.len(), 10);
    assert_eq!(control.snapshot().total_blocked, 12);
}

#[test]
fn snapshot_orders_runtime_domains_by_hits_then_domain() {
    let blocker = blocker(&config(), &[], None);
    let control: &dyn BlockerControl = &blocker;
    assert_eq!(
        add(
            control,
            BlockListKind::Deny,
            "b.example.net\na.example.net\nc.example.net"
        ),
        3
    );

    let _ = blocker.decide(&query("a.example.net"), &context(None));
    let _ = blocker.decide(&query("b.example.net"), &context(None));
    let _ = blocker.decide(&query("b.example.net"), &context(None));
    let _ = blocker.decide(&query("c.example.net"), &context(None));

    let domains = control.snapshot().domains;
    assert_eq!(domains[0].domain, "b.example.net");
    assert_eq!(domains[0].hits, 2);
    assert_eq!(domains[1].domain, "a.example.net");
    assert_eq!(domains[2].domain, "c.example.net");
}

#[test]
fn snapshot_reports_enabled_and_disabled_list_statuses() {
    let dir = temp_dir("snapshot-lists");
    let active = dir.join("active.txt");
    let inactive = dir.join("inactive.txt");
    fs::write(&active, "one.example.net\n").expect("active list");
    fs::write(&inactive, "two.example.net\n").expect("inactive list");

    let mut config = config();
    config.lists_dir = dir.clone();
    config.categories = vec![BlockCategory::Advertising];
    config.lists = vec![
        source("active", "active.txt", BlockCategory::Advertising, true),
        source("disabled", "active.txt", BlockCategory::Advertising, false),
        source(
            "inactive-category",
            "inactive.txt",
            BlockCategory::Malware,
            true,
        ),
    ];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;
    let lists = control.snapshot().lists;

    assert_eq!(lists.len(), 3);
    assert!(lists[0].enabled);
    assert_eq!(lists[0].entries, 1);
    assert!(!lists[1].enabled);
    assert_eq!(lists[1].entries, 0);
    assert!(!lists[2].enabled);
    assert_eq!(lists[2].entries, 0);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reload_lists_keeps_old_rules_when_the_file_disappears() {
    let dir = temp_dir("reload-missing");
    let file = dir.join("ads.txt");
    fs::write(&file, "ads.example.net\n").expect("initial list");

    let mut config = config();
    config.lists_dir = dir.clone();
    config.lists = vec![source("ads", "ads.txt", BlockCategory::Advertising, true)];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    fs::remove_file(&file).expect("remove list");
    assert!(control.reload_lists().is_err());
    assert_eq!(
        blocker.decide(&query("ads.example.net"), &context(None)),
        Decision::Block
    );
    assert_eq!(control.snapshot().lists[0].entries, 1);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reload_lists_invalidates_cached_decisions() {
    let dir = temp_dir("reload-cache");
    let file = dir.join("ads.txt");
    fs::write(&file, "first.example.net\n").expect("initial list");

    let mut config = config();
    config.lists_dir = dir.clone();
    config.lists = vec![source("ads", "ads.txt", BlockCategory::Advertising, true)];
    let cache = PolicyCacheConfig {
        enabled: true,
        max_entries: 8,
    };
    let blocker = blocker(&config, &[], Some(&cache));
    let control: &dyn BlockerControl = &blocker;

    assert_eq!(
        blocker.decide(&query("first.example.net"), &context(None)),
        Decision::Block
    );
    assert_eq!(blocker.cached_decisions(), 1);

    fs::write(&file, "second.example.net\n").expect("updated list");
    assert_eq!(reload(control), 1);
    assert_eq!(blocker.cached_decisions(), 0);
    assert_eq!(
        blocker.decide(&query("first.example.net"), &context(None)),
        Decision::Allow
    );
    assert_eq!(
        blocker.decide(&query("second.example.net"), &context(None)),
        Decision::Block
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn disabled_remote_and_missing_sources_are_accepted_and_ignored() {
    let dir = temp_dir("disabled-sources");
    let mut config = config();
    config.lists_dir = dir.clone();
    config.lists = vec![
        source(
            "remote",
            "https://example.net/list.txt",
            BlockCategory::Custom,
            false,
        ),
        source(
            "missing",
            "does-not-exist.txt",
            BlockCategory::Custom,
            false,
        ),
    ];

    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;
    assert_eq!(reload(control), 0);
    assert!(control.snapshot().lists.iter().all(|list| !list.enabled));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn absolute_list_paths_are_loaded() {
    let dir = temp_dir("absolute-list");
    let file = dir.join("ads.txt");
    fs::write(&file, "ads.example.net\n").expect("list file");

    let mut config = config();
    config.lists_dir = temp_dir("unused-list-dir");
    config.lists = vec![source(
        "ads",
        file.to_string_lossy().as_ref(),
        BlockCategory::Advertising,
        true,
    )];
    let blocker = blocker(&config, &[], None);
    let control: &dyn BlockerControl = &blocker;

    assert_eq!(
        blocker.decide(&query("ads.example.net"), &context(None)),
        Decision::Block
    );
    assert_eq!(control.snapshot().lists[0].entries, 1);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_queries_and_control_changes_remain_consistent() {
    let mut config = config();
    config.denylist = vec!["ads.example.com".to_owned()];
    let blocker = Arc::new(blocker(&config, &[], None));
    let barrier = Arc::new(Barrier::new(5));
    let mut workers = Vec::new();

    for index in 0..4 {
        let worker = Arc::clone(&blocker);
        let start = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            start.wait();
            for round in 0..200 {
                let name = if round % 2 == 0 {
                    "ads.example.com".to_owned()
                } else {
                    format!("dynamic{index}.example.net")
                };
                let _ = worker.decide(&query(&name), &context(None));
            }
        }));
    }

    let controller = Arc::clone(&blocker);
    let start = Arc::clone(&barrier);
    workers.push(thread::spawn(move || {
        start.wait();
        for round in 0..100 {
            controller.set_enabled(round % 2 == 0);
            if round % 10 == 0 {
                let _ = controller.add_domains(
                    BlockListKind::Deny,
                    &format!("dynamic{}.example.net", round % 4),
                );
            }
            let _ = controller.snapshot();
        }
    }));

    for worker in workers {
        worker.join().expect("worker thread must not panic");
    }

    let control: &dyn BlockerControl = blocker.as_ref();
    control.set_enabled(true);
    assert_eq!(
        blocker.decide(&query("ads.example.com"), &context(None)),
        Decision::Block
    );
    assert!(control.snapshot().total_blocked > 0);
}

#[test]
fn control_errors_use_the_core_error_type() {
    let error = Error::Runtime("forced failure".to_owned());
    assert_eq!(error.to_string(), "forced failure");
}
