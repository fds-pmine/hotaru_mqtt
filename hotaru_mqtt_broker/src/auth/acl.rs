//! `JsonAclChecker` — akari JSON-backed `AclChecker`.
//!
//! Schema (single-tenant):
//! ```json
//! {
//!   "users": {
//!     "alice": {
//!       "password": "$pbkdf2-sha512$...",
//!       "acl": {
//!         "publish":   ["sensors/+/temp", "house/alice/#"],
//!         "subscribe": ["sensors/+/temp", "house/alice/#", "$SYS/broker/version"]
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Multi-tenant: wrap the above in `tenants.<id>.users.<name>.acl`.
//!
//! Decision rule (publish): topic is concrete. Allow iff some entry in
//! `acl.publish` matches the topic via the broker's canonical
//! [`crate::broker::filter_matches`].
//!
//! Decision rule (subscribe): the requested filter is checked against
//! `acl.subscribe` using the SAME `filter_matches` — wildcards in the
//! requested filter are treated as literal segments. This mirrors how
//! mosquitto's acl_file is commonly understood: subscribing to broader
//! patterns generally requires an equally-broad allowed entry.
//!
//! Missing user / missing `acl` section / missing `acl.<kind>` → empty
//! allow-list → Deny. Catches the "forgot to grant" case cleanly.

use std::sync::Arc;

use async_trait::async_trait;
use hotaru_core::Value;

use crate::broker::filter_matches;
use crate::traits::{AclChecker, AclDecision, TenantId};

pub struct JsonAclChecker {
    snapshot: Value,
}

impl JsonAclChecker {
    pub fn from_str(json: &str) -> Result<Self, String> {
        Ok(Self {
            snapshot: Value::from_json(json)?,
        })
    }

    pub fn from_path(path: impl AsRef<str>) -> Result<Self, String> {
        Ok(Self {
            snapshot: Value::from_jsonf(path.as_ref())?,
        })
    }

    pub fn from_snapshot(snapshot: Value) -> Self {
        Self { snapshot }
    }

    fn user_value(&self, tenant: Option<&TenantId>, username: &str) -> Option<&Value> {
        let users = match tenant {
            Some(tid) => {
                let tenants = match &self.snapshot {
                    Value::Dict(m) => m.get("tenants")?,
                    _ => return None,
                };
                let tenant_obj = match tenants {
                    Value::Dict(m) => m.get(tid.as_ref())?,
                    _ => return None,
                };
                match tenant_obj {
                    Value::Dict(m) => m.get("users")?,
                    _ => return None,
                }
            }
            None => match &self.snapshot {
                Value::Dict(m) => m.get("users")?,
                _ => return None,
            },
        };
        match users {
            Value::Dict(m) => m.get(username),
            _ => None,
        }
    }

    fn allowed_patterns(
        &self,
        tenant: Option<&TenantId>,
        username: Option<&Arc<str>>,
        kind: &str,
    ) -> Vec<String> {
        let Some(username) = username else {
            return Vec::new();
        };
        let Some(user) = self.user_value(tenant, username) else {
            return Vec::new();
        };
        let acl = match user {
            Value::Dict(m) => match m.get("acl") {
                Some(v) => v,
                None => return Vec::new(),
            },
            _ => return Vec::new(),
        };
        let list = match acl {
            Value::Dict(m) => match m.get(kind) {
                Some(Value::List(l)) => l,
                _ => return Vec::new(),
            },
            _ => return Vec::new(),
        };
        list.iter()
            .filter_map(|v| match v {
                Value::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect()
    }
}

#[async_trait]
impl AclChecker for JsonAclChecker {
    async fn check_subscribe(
        &self,
        tenant: Option<&TenantId>,
        _client_id: &Arc<str>,
        username: Option<&Arc<str>>,
        filter: &str,
    ) -> AclDecision {
        let allowed = self.allowed_patterns(tenant, username, "subscribe");
        // Treat the requested filter's segments as the haystack so wildcards
        // in the request are NOT auto-promoted to "matches anything".
        let segs: Vec<&str> = filter.split('/').collect();
        if allowed.iter().any(|a| filter_matches(a, &segs)) {
            AclDecision::Allow
        } else {
            AclDecision::Deny
        }
    }

    async fn check_publish(
        &self,
        tenant: Option<&TenantId>,
        _client_id: &Arc<str>,
        username: Option<&Arc<str>>,
        topic: &str,
    ) -> AclDecision {
        let allowed = self.allowed_patterns(tenant, username, "publish");
        let segs: Vec<&str> = topic.split('/').collect();
        if allowed.iter().any(|a| filter_matches(a, &segs)) {
            AclDecision::Allow
        } else {
            AclDecision::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Arc<str> {
        Arc::from("alice")
    }
    fn cid() -> Arc<str> {
        Arc::from("client-1")
    }

    #[tokio::test]
    async fn publish_allowed_pattern_grants() {
        let acl = JsonAclChecker::from_str(
            r#"{"users":{"alice":{"acl":{"publish":["sensors/+/temp"]}}}}"#,
        )
        .unwrap();
        let d = acl
            .check_publish(None, &cid(), Some(&alice()), "sensors/kitchen/temp")
            .await;
        assert_eq!(d, AclDecision::Allow);
    }

    #[tokio::test]
    async fn publish_unrelated_topic_denied() {
        let acl = JsonAclChecker::from_str(
            r#"{"users":{"alice":{"acl":{"publish":["sensors/+/temp"]}}}}"#,
        )
        .unwrap();
        let d = acl
            .check_publish(None, &cid(), Some(&alice()), "ops/secret/dump")
            .await;
        assert_eq!(d, AclDecision::Deny);
    }

    #[tokio::test]
    async fn subscribe_requires_covering_pattern() {
        let acl = JsonAclChecker::from_str(
            r##"{"users":{"alice":{"acl":{"subscribe":["house/alice/#"]}}}}"##,
        )
        .unwrap();
        // Allowed pattern covers requested filter.
        let allow = acl
            .check_subscribe(None, &cid(), Some(&alice()), "house/alice/temp")
            .await;
        assert_eq!(allow, AclDecision::Allow);
        // Requested filter outside the granted namespace.
        let deny = acl
            .check_subscribe(None, &cid(), Some(&alice()), "house/bob/temp")
            .await;
        assert_eq!(deny, AclDecision::Deny);
    }

    #[tokio::test]
    async fn missing_acl_section_denies_by_default() {
        let acl = JsonAclChecker::from_str(r#"{"users":{"alice":{}}}"#).unwrap();
        let d = acl
            .check_publish(None, &cid(), Some(&alice()), "x/y")
            .await;
        assert_eq!(
            d,
            AclDecision::Deny,
            "no ACL config MUST default-deny, not default-allow"
        );
    }

    #[tokio::test]
    async fn anonymous_user_denied() {
        // Authenticator might accept-all; ACL must still deny when there's
        // no username to look up.
        let acl = JsonAclChecker::from_str(r##"{"users":{"alice":{"acl":{"publish":["#"]}}}}"##)
            .unwrap();
        let d = acl.check_publish(None, &cid(), None, "x/y").await;
        assert_eq!(d, AclDecision::Deny);
    }

    #[tokio::test]
    async fn tenant_scope_isolates_acl() {
        let acl = JsonAclChecker::from_str(
            r#"{
                "tenants": {
                    "ta": {"users": {"alice": {"acl": {"publish": ["a/#"]}}}},
                    "tb": {"users": {"alice": {"acl": {"publish": ["b/#"]}}}}
                }
            }"#,
        )
        .unwrap();
        let ta: TenantId = Arc::from("ta");
        let tb: TenantId = Arc::from("tb");

        // alice@ta can publish a/x but not b/x.
        assert_eq!(
            acl.check_publish(Some(&ta), &cid(), Some(&alice()), "a/x").await,
            AclDecision::Allow
        );
        assert_eq!(
            acl.check_publish(Some(&ta), &cid(), Some(&alice()), "b/x").await,
            AclDecision::Deny
        );
        // alice@tb is the inverse.
        assert_eq!(
            acl.check_publish(Some(&tb), &cid(), Some(&alice()), "b/x").await,
            AclDecision::Allow
        );
        assert_eq!(
            acl.check_publish(Some(&tb), &cid(), Some(&alice()), "a/x").await,
            AclDecision::Deny
        );
    }

    #[tokio::test]
    async fn dollar_sys_subscribe_requires_explicit_grant() {
        // spec §4.7.2 + AOI §5.1.1 — even with `#` ACL, a $SYS topic should
        // NOT be reachable via wildcard. Explicit `$SYS/#` grant required.
        let acl = JsonAclChecker::from_str(
            r##"{"users":{"alice":{"acl":{"subscribe":["#"]}}}}"##,
        )
        .unwrap();
        let d = acl
            .check_subscribe(None, &cid(), Some(&alice()), "$SYS/broker/version")
            .await;
        assert_eq!(
            d,
            AclDecision::Deny,
            "wildcard `#` MUST NOT reach $-prefixed topics per spec §4.7.2"
        );

        let acl2 = JsonAclChecker::from_str(
            r##"{"users":{"alice":{"acl":{"subscribe":["$SYS/#"]}}}}"##,
        )
        .unwrap();
        let d2 = acl2
            .check_subscribe(None, &cid(), Some(&alice()), "$SYS/broker/version")
            .await;
        assert_eq!(d2, AclDecision::Allow);
    }
}
