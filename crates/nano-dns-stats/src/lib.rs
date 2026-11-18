//! Lock-protected in-memory statistics for completed DNS queries.
//!
//! The implementation keeps a time-ordered ring of recent events. A snapshot
//! derives all counters from that ring so expired entries disappear without a
//! background cleanup task.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nano_dns_core::config::StatsConfig;
use nano_dns_core::error::{Error as CoreError, Result};
use nano_dns_core::model::{Decision, QueryEvent, StatsSnapshot, Transport};
use nano_dns_core::traits::StatsSink;

/// Maximum number of domains returned by [`StatsCollector::snapshot`].
const TOP_DOMAINS: usize = 10;

/// In-memory statistics collector with time-based retention.
pub struct StatsCollector {
    inner: Mutex<Inner>,
}

struct Inner {
    retention: Duration,
    events: VecDeque<QueryEvent>,
}

impl StatsCollector {
    /// Create a collector from configuration.
    pub fn new(config: &StatsConfig) -> Self {
        Self {
            inner: Mutex::new(Inner {
                retention: Duration::from_secs(config.retention_secs),
                events: VecDeque::new(),
            }),
        }
    }

    /// Record a completed query.
    pub fn record_event(&self, event: QueryEvent) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        inner.record(event);
        Ok(())
    }

    /// Return counters for the configured retention window.
    pub fn snapshot(&self) -> Result<StatsSnapshot> {
        let mut inner = self.inner.lock().map_err(|_| poisoned())?;
        Ok(inner.snapshot())
    }
}

impl StatsSink for StatsCollector {
    fn record(&self, event: &QueryEvent) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.record(event.clone());
        }
    }

    fn snapshot(&self) -> StatsSnapshot {
        StatsCollector::snapshot(self).unwrap_or_default()
    }
}

impl Inner {
    fn record(&mut self, event: QueryEvent) {
        self.evict(event.timestamp_ms);
        self.events.push_back(event);
    }

    fn snapshot(&mut self) -> StatsSnapshot {
        self.evict(now_ms());

        let mut snapshot = StatsSnapshot {
            top_domains_capacity: TOP_DOMAINS,
            ..StatsSnapshot::default()
        };
        let mut domains: HashMap<&str, u64> = HashMap::new();

        for event in &self.events {
            snapshot.total_queries += 1;
            match event.decision {
                Decision::Allow => snapshot.allowed += 1,
                Decision::Block => snapshot.blocked += 1,
            }
            *snapshot
                .response_codes
                .entry(event.response_code)
                .or_default() += 1;
            *snapshot.query_types.entry(event.query_type).or_default() += 1;
            *snapshot
                .transports
                .entry(transport_name(event.transport).to_owned())
                .or_default() += 1;
            if event.cache_hit {
                snapshot.cache_hits += 1;
            }
            if event.response_code == SERVFAIL_CODE {
                snapshot.errors += 1;
            }
            *domains.entry(event.name.as_str()).or_default() += 1;
        }

        snapshot.top_domains = domains
            .into_iter()
            .map(|(name, count)| (name.to_owned(), count))
            .collect::<Vec<_>>();
        snapshot
            .top_domains
            .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        snapshot.top_domains.truncate(TOP_DOMAINS);
        snapshot
    }

    fn evict(&mut self, now_ms: u64) {
        let retention_ms = u128::from(self.retention.as_millis());
        while let Some(event) = self.events.front() {
            let event_ms = u128::from(event.timestamp_ms);
            let expired = event_ms > u128::from(now_ms)
                || u128::from(now_ms).saturating_sub(event_ms) > retention_ms;
            if !expired {
                break;
            }
            self.events.pop_front();
        }
    }
}

/// Numeric DNS SERVFAIL response code, kept local to avoid a Hickory dependency.
const SERVFAIL_CODE: u16 = 2;

fn poisoned() -> CoreError {
    CoreError::Runtime("statistics lock poisoned".to_owned())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Dot => "dot",
        Transport::Doh => "doh",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn event(name: &str, timestamp_ms: u64, code: u16, decision: Decision) -> QueryEvent {
        QueryEvent {
            timestamp_ms,
            client_id: None,
            client_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            transport: Transport::Udp,
            name: name.to_owned(),
            query_type: 1,
            query_class: 1,
            decision,
            response_code: code,
            ttl_secs: 60,
            negative: false,
            cache_hit: false,
        }
    }

    #[test]
    fn snapshots_aggregate_recorded_queries() {
        let collector = StatsCollector::new(&StatsConfig {
            enabled: true,
            retention_secs: 60,
        });
        collector
            .record_event(event("allowed.example.", now_ms(), 0, Decision::Allow))
            .expect("event must be recorded");
        collector
            .record_event(event("blocked.example.", now_ms(), 3, Decision::Block))
            .expect("event must be recorded");
        collector
            .record_event(event("failed.example.", now_ms(), 2, Decision::Allow))
            .expect("event must be recorded");

        let snapshot = collector.snapshot().expect("snapshot must succeed");
        assert_eq!(snapshot.total_queries, 3);
        assert_eq!(snapshot.allowed, 2);
        assert_eq!(snapshot.blocked, 1);
        assert_eq!(snapshot.errors, 1);
        assert_eq!(snapshot.response_codes.get(&3), Some(&1));
        assert_eq!(snapshot.query_types.get(&1), Some(&3));
        assert_eq!(snapshot.transports.get("udp"), Some(&3));
        assert_eq!(snapshot.top_domains.len(), 3);
    }

    #[test]
    fn expired_events_are_ignored() {
        let collector = StatsCollector::new(&StatsConfig {
            enabled: true,
            retention_secs: 1,
        });
        collector
            .record_event(event("old.example.", 1, 0, Decision::Allow))
            .expect("event must be recorded");
        collector
            .record_event(event("current.example.", now_ms(), 0, Decision::Allow))
            .expect("event must be recorded");

        let snapshot = collector.snapshot().expect("snapshot must succeed");
        assert_eq!(snapshot.total_queries, 1);
        assert_eq!(snapshot.top_domains[0].0, "current.example.");
    }

    #[test]
    fn cache_hits_are_counted() {
        let collector = StatsCollector::new(&StatsConfig::default());
        let mut event = event("cached.example.", now_ms(), 0, Decision::Allow);
        event.cache_hit = true;
        collector
            .record_event(event)
            .expect("event must be recorded");
        let snapshot = collector.snapshot().expect("snapshot must succeed");
        assert_eq!(snapshot.cache_hits, 1);
    }

    #[test]
    fn trait_methods_match_direct_methods() {
        let collector = StatsCollector::new(&StatsConfig::default());
        let event = event("example.com.", now_ms(), 0, Decision::Allow);
        StatsSink::record(&collector, &event);
        let snapshot = StatsSink::snapshot(&collector);
        assert_eq!(snapshot.total_queries, 1);
    }
}
