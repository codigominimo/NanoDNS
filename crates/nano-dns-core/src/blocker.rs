//! Runtime control interface for the optional blocking subsystem.
//!
//! The core crate only defines the interface and plain data types. The
//! implementation lives in `nano-dns-blocker`, so management surfaces such as
//! the web dashboard can control filtering without depending on it.

use crate::error::Result;

/// Which side of the filtering rules a domain belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockListKind {
    /// Domains that are always allowed.
    Allow,
    /// Domains that are blocked.
    Deny,
}

impl BlockListKind {
    /// Stable lowercase name used by forms and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Status of one configured local list file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockListStatus {
    /// Configured list identifier.
    pub id: String,
    /// Human-readable list name.
    pub name: String,
    /// Configured category.
    pub category: String,
    /// Configured file path or source string.
    pub source: String,
    /// Whether the list is enabled and its category is active.
    pub enabled: bool,
    /// Number of domains currently loaded from the file.
    pub entries: usize,
}

/// One domain added at runtime, with its observed block count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedDomain {
    /// Normalized domain, including wildcard-derived parent domains.
    pub domain: String,
    /// Whether the domain is an allow or deny rule.
    pub kind: BlockListKind,
    /// Number of queries blocked by this rule since startup.
    pub hits: u64,
}

/// Read-only view of the blocker's mutable state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockerSnapshot {
    /// Whether filtering is currently active.
    pub enabled: bool,
    /// Total number of blocked queries since startup.
    pub total_blocked: u64,
    /// Runtime rules, ordered by block count and then by domain.
    pub domains: Vec<BlockedDomain>,
    /// Most frequently blocked query names, ordered by count.
    pub top_blocked: Vec<(String, u64)>,
    /// Configured local lists and their current entry counts.
    pub lists: Vec<BlockListStatus>,
}

/// Mutable control over the running blocker.
///
/// All operations are safe to call concurrently with query processing. Every
/// rule change invalidates cached decisions so the next query sees the new
/// state immediately.
pub trait BlockerControl: Send + Sync {
    /// Return a consistent snapshot of the current state.
    fn snapshot(&self) -> BlockerSnapshot;

    /// Whether filtering is currently active.
    fn is_enabled(&self) -> bool;

    /// Enable or disable filtering at runtime.
    fn set_enabled(&self, enabled: bool);

    /// Add domains from a list in presentation format.
    ///
    /// Accepts plain domains, wildcard prefixes, adblock rules and hosts-file
    /// rows. Returns the number of distinct domains added.
    fn add_domains(&self, kind: BlockListKind, text: &str) -> Result<usize>;

    /// Remove one runtime domain. Returns `true` when a rule was removed.
    ///
    /// Domains loaded from configuration or list files are not modified.
    fn remove_domain(&self, kind: BlockListKind, domain: &str) -> Result<bool>;

    /// Remove every runtime domain of `kind`. Returns the number removed.
    fn clear_domains(&self, kind: BlockListKind) -> usize;

    /// Re-read configured local list files. Returns the number of domains.
    fn reload_lists(&self) -> Result<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_list_kind_has_stable_names() {
        assert_eq!(BlockListKind::Allow.as_str(), "allow");
        assert_eq!(BlockListKind::Deny.as_str(), "deny");
    }

    #[test]
    fn snapshot_defaults_to_disabled() {
        let snapshot = BlockerSnapshot::default();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.total_blocked, 0);
        assert!(snapshot.domains.is_empty());
        assert!(snapshot.lists.is_empty());
    }
}
