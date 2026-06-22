//! `JsonAuthenticator` — akari JSON-backed `Authenticator`.
//!
//! Expected schema (single-tenant):
//! ```json
//! {
//!   "users": {
//!     "alice": { "password": "$pbkdf2-sha512$rounds=10000$<salt>$<hash>" },
//!     "bob":   { "password": "..." }
//!   }
//! }
//! ```
//!
//! Multi-tenant:
//! ```json
//! {
//!   "tenants": {
//!     "tenant-a": {
//!       "users": { "alice": { "password": "..." } }
//!     }
//!   }
//! }
//! ```
//!
//! `tenant=None` in the `Authenticator::authenticate` call selects the
//! single-tenant lookup; `Some(tid)` reads from `tenants.<tid>.users.<n>.password`.
//!
//! Hot-reload (mtime-based) is Stage A P8 (config split) — for now the
//! snapshot is loaded once at construction time.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose;
use hmac::Hmac;
use hotaru_core::Value;
use hotaru_mqtt::packet::ConnackReturnCode;
use hotaru_mqtt::packet::ConnectPacket;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use tracing::error;

use crate::auth::password::{DefaultPasswordVerifier, PasswordHash, PasswordVerifier};
use crate::traits::{AuthResult, Authenticator, TenantId};

/// PBKDF2 rounds used to manufacture the in-memory dummy hash. Calibrated to
/// mosquitto_passwd's default (10_000). Production deployments whose real
/// users hash at a different cost should match this via
/// [`JsonAuthenticator::with_dummy_rounds`] so unknown-user verify cost
/// stays indistinguishable from known-user cost.
const DEFAULT_DUMMY_ROUNDS: u32 = 10_000;

pub struct JsonAuthenticator {
    snapshot: Value,
    verifier: Arc<dyn PasswordVerifier>,
    /// Constant-cost decoy hash used on every reject path so unknown-user
    /// vs. wrong-password are indistinguishable by wall-clock (audit finding
    /// F3 — username enumeration timing oracle).
    dummy_hash: String,
}

impl JsonAuthenticator {
    /// Construct from a JSON string. Returns the akari parse error string on
    /// failure — caller surfaces it in their own error wrapping.
    ///
    /// SAFETY_PROOF v5 §7 F2 closure: rejects mixed-rounds snapshots
    /// (`> 1` distinct PBKDF2 `rounds` value) at load time. Previously this
    /// path emitted a `warn!` and silently fell back to modal rounds, leaving
    /// the non-modal subset of users timing-distinguishable from unknown
    /// users. Uniform / empty / all-bcrypt snapshots load unchanged.
    pub fn from_str(json: &str) -> Result<Self, String> {
        let snapshot = Value::from_json(json)?;
        Self::with_snapshot(snapshot)
    }

    /// Construct by reading a JSON file at `path`. See [`Self::from_str`] —
    /// same fail-closed semantics on mixed rounds.
    pub fn from_path(path: impl AsRef<str>) -> Result<Self, String> {
        let snapshot = Value::from_jsonf(path.as_ref())?;
        Self::with_snapshot(snapshot)
    }

    /// Strict variant (SAFETY_PROOF v3 U4 closure): rejects snapshots in
    /// which users hash at non-uniform PBKDF2 rounds. The modal-rounds
    /// fallback in [`Self::from_str`] hides the timing leak for the
    /// majority of users but leaves outliers (e.g. a `rounds=1_000_000`
    /// VIP among `rounds=10_000` masses) distinguishable from the
    /// unknown-user response by wall-clock. This constructor enforces
    /// uniformity at load time so the per-user verify cost is provably
    /// indistinguishable from the dummy.
    pub fn from_str_strict(json: &str) -> Result<Self, String> {
        let snapshot = Value::from_json(json)?;
        let rounds = detect_uniform_rounds(&snapshot)?;
        Ok(Self {
            verifier: Arc::new(DefaultPasswordVerifier),
            dummy_hash: build_dummy_phc(rounds),
            snapshot,
        })
    }

    /// Strict file variant (see [`Self::from_str_strict`]).
    pub fn from_path_strict(path: impl AsRef<str>) -> Result<Self, String> {
        let snapshot = Value::from_jsonf(path.as_ref())?;
        let rounds = detect_uniform_rounds(&snapshot)?;
        Ok(Self {
            verifier: Arc::new(DefaultPasswordVerifier),
            dummy_hash: build_dummy_phc(rounds),
            snapshot,
        })
    }

    fn with_snapshot(snapshot: Value) -> Result<Self, String> {
        // G4 mitigation: scan the snapshot at construction time, pick the
        // modal `rounds` value from every parseable PHC, and seed the
        // dummy with that. Empty snapshot or all-bcrypt snapshot falls
        // back to `DEFAULT_DUMMY_ROUNDS`.
        //
        // SAFETY_PROOF v5 §7 F2 closure (replaces R6's loud-warn): when
        // the snapshot has more than one distinct PBKDF2 `rounds` value,
        // **reject at load time**. Modal fallback is no longer permitted
        // because non-modal users stay timing-distinguishable from unknown
        // users — the warn-and-continue path was a silent timing-leak vector
        // unless the operator independently noticed the log line. Strict
        // is now the only mode; `from_str_strict` is kept as an alias that
        // *also* rejects empty / all-bcrypt snapshots (no PBKDF2 anchor).
        let distinct = count_distinct_rounds(&snapshot);
        if distinct > 1 {
            error!(
                target: "hotaru_mqtt_broker",
                distinct_rounds = distinct,
                "JsonAuthenticator: snapshot has multiple PBKDF2 `rounds` values; \
                 rejected at load time. Non-modal users would be timing-distinguishable \
                 from unknown users — re-hash all entries to a single `rounds` setting \
                 before retrying."
            );
            return Err(format!(
                "JsonAuthenticator: snapshot has {distinct} distinct PBKDF2 `rounds` \
                 values; refusing to load (SAFETY_PROOF v5 §7 F2). Re-hash all entries \
                 to a single `rounds` setting."
            ));
        }
        let rounds = detect_modal_rounds(&snapshot).unwrap_or(DEFAULT_DUMMY_ROUNDS);
        Ok(Self {
            snapshot,
            verifier: Arc::new(DefaultPasswordVerifier),
            dummy_hash: build_dummy_phc(rounds),
        })
    }

    /// Override the default PBKDF2-SHA512 verifier (e.g. inject a fake in
    /// tests, or layer caching atop the real one).
    pub fn with_verifier(mut self, verifier: Arc<dyn PasswordVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Recalibrate the dummy hash to match the rounds your real users use.
    /// See [`DEFAULT_DUMMY_ROUNDS`] for the rationale.
    pub fn with_dummy_rounds(mut self, rounds: u32) -> Self {
        self.dummy_hash = build_dummy_phc(rounds);
        self
    }

    /// Resolve `users.<username>.password` for the given tenant. Returns
    /// `None` when any segment is absent or non-string.
    fn lookup_hash(&self, tenant: Option<&TenantId>, username: &str) -> Option<&str> {
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
        let user = match users {
            Value::Dict(m) => m.get(username)?,
            _ => return None,
        };
        let pw = match user {
            Value::Dict(m) => m.get("password")?,
            _ => return None,
        };
        match pw {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

#[async_trait]
impl Authenticator for JsonAuthenticator {
    async fn authenticate(
        &self,
        tenant: Option<&TenantId>,
        connect: &ConnectPacket,
        _remote_addr: Option<SocketAddr>,
    ) -> AuthResult {
        // F3 mitigation: every reject path MUST run the verifier exactly once
        // so wall-clock cost is identical for missing-username, missing-
        // password, unknown-user, and wrong-password. Returning early without
        // verifying leaks "this username exists" via a microsecond-scale
        // latency cliff (PBKDF2 dominates).
        let username = connect.username.as_ref();
        let password = connect.password.as_ref();

        let stored_hash = username
            .and_then(|u| self.lookup_hash(tenant, u))
            .unwrap_or(self.dummy_hash.as_str());
        // SAFETY_PROOF v5 §7 F1 / #69 closure: `ConnectPacket.password` is now
        // `Option<Zeroizing<Vec<u8>>>`, wiped at packet drop. We no longer
        // need the prior R6 local `Zeroizing<Vec<u8>>` copy — the source IS
        // the zeroized buffer. Borrow a slice straight into the verifier.
        let candidate_slice: &[u8] = password.map(|p| p.as_slice()).unwrap_or(&[]);
        let hash_ok = self.verifier.verify(stored_hash, candidate_slice);

        // Accept only if (a) the username, password, and stored hash all
        // really existed, AND (b) the verifier reported a match against the
        // *real* hash. The lookup re-check is necessary because the verifier
        // ran against the dummy when the user was unknown.
        let user_exists = username.is_some_and(|u| self.lookup_hash(tenant, u).is_some());
        if hash_ok && user_exists && password.is_some() {
            AuthResult::accept()
        } else {
            AuthResult::reject(ConnackReturnCode::BadUsernameOrPassword)
        }
    }
}

/// Walk every PHC string under `users.*.password` (single-tenant) and
/// `tenants.*.users.*.password` (multi-tenant), parse each as a
/// `PasswordHash::Pbkdf2Sha512`, collect the rounds, and return the
/// modal value. Returns `None` when the snapshot is empty, has no PBKDF2
/// hashes, or only contains bcrypt entries.
fn detect_modal_rounds(snapshot: &Value) -> Option<u32> {
    let mut counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    if let Value::Dict(top) = snapshot {
        if let Some(Value::Dict(users)) = top.get("users") {
            collect_user_rounds(users, &mut counts);
        }
        if let Some(Value::Dict(tenants)) = top.get("tenants") {
            for (_, tenant) in tenants.iter() {
                if let Value::Dict(t) = tenant
                    && let Some(Value::Dict(users)) = t.get("users")
                {
                    collect_user_rounds(users, &mut counts);
                }
            }
        }
    }
    counts.into_iter().max_by_key(|&(_, c)| c).map(|(r, _)| r)
}

/// SAFETY_PROOF v5 §7 F2: cheap distinct-count probe used by
/// `with_snapshot` to decide whether to **reject** the snapshot at load
/// time. Walks the same shape as `detect_modal_rounds` /
/// `detect_uniform_rounds` and returns the size of the
/// `(rounds → count)` map. `0` for empty / all-bcrypt; `1` for uniform;
/// `> 1` triggers fail-closed (the prior R6 loud-warn-and-continue path
/// was promoted to a hard reject because operators routinely miss `warn!`
/// lines in dev consoles).
fn count_distinct_rounds(snapshot: &Value) -> usize {
    let mut counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    if let Value::Dict(top) = snapshot {
        if let Some(Value::Dict(users)) = top.get("users") {
            collect_user_rounds(users, &mut counts);
        }
        if let Some(Value::Dict(tenants)) = top.get("tenants") {
            for (_, tenant) in tenants.iter() {
                if let Value::Dict(t) = tenant
                    && let Some(Value::Dict(users)) = t.get("users")
                {
                    collect_user_rounds(users, &mut counts);
                }
            }
        }
    }
    counts.len()
}

/// U4 strict variant: walk the snapshot's PBKDF2 PHCs and require ALL
/// to share the same `rounds`. Returns `Err` if rounds disagree, or if
/// there are no parseable PBKDF2 hashes (then the caller can't pin a
/// dummy cost to anything observable).
fn detect_uniform_rounds(snapshot: &Value) -> Result<u32, String> {
    let mut counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    if let Value::Dict(top) = snapshot {
        if let Some(Value::Dict(users)) = top.get("users") {
            collect_user_rounds(users, &mut counts);
        }
        if let Some(Value::Dict(tenants)) = top.get("tenants") {
            for (_, tenant) in tenants.iter() {
                if let Value::Dict(t) = tenant
                    && let Some(Value::Dict(users)) = t.get("users")
                {
                    collect_user_rounds(users, &mut counts);
                }
            }
        }
    }
    match counts.len() {
        0 => Err(
            "snapshot has no PBKDF2 users — strict mode cannot pin a dummy rounds value".to_owned(),
        ),
        1 => Ok(counts.into_iter().next().map(|(r, _)| r).unwrap()),
        n => Err(format!(
            "snapshot has {n} distinct PBKDF2 `rounds` values; strict mode requires \
             a single rounds setting across all users (SAFETY_PROOF v3 U4)"
        )),
    }
}

fn collect_user_rounds(
    users: &std::collections::HashMap<String, Value>,
    counts: &mut std::collections::HashMap<u32, usize>,
) {
    for (_, user) in users.iter() {
        if let Value::Dict(u) = user
            && let Some(Value::Str(pw)) = u.get("password")
            && let Some(PasswordHash::Pbkdf2Sha512 { rounds, .. }) = PasswordHash::parse(pw)
        {
            *counts.entry(rounds).or_insert(0) += 1;
        }
    }
}

/// Generate a syntactically-real PHC hash of a fixed throwaway password.
/// The salt is fixed too — there's no security relevance because the dummy
/// hash is never compared for "match", only used to burn equivalent CPU.
fn build_dummy_phc(rounds: u32) -> String {
    let salt: &[u8] = b"hotaru-mqtt-dummy-salt-v1";
    let mut hash = vec![0u8; 32];
    // Failure here would indicate broken HMAC init, which would also break
    // every real lookup — surface immediately rather than silently shipping
    // a dummy that the verifier can't parse.
    pbkdf2::<Hmac<Sha512>>(b"hotaru-mqtt-dummy-pw", salt, rounds, &mut hash)
        .expect("dummy PBKDF2 must succeed");
    format!(
        "$pbkdf2-sha512$rounds={}${}${}",
        rounds,
        general_purpose::STANDARD_NO_PAD.encode(salt),
        general_purpose::STANDARD_NO_PAD.encode(&hash),
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn make_phc(password: &[u8], salt: &[u8], rounds: u32) -> String {
        let mut hash = vec![0u8; 32];
        pbkdf2::<Hmac<Sha512>>(password, salt, rounds, &mut hash).unwrap();
        format!(
            "$pbkdf2-sha512$rounds={}${}${}",
            rounds,
            general_purpose::STANDARD_NO_PAD.encode(salt),
            general_purpose::STANDARD_NO_PAD.encode(&hash),
        )
    }

    fn connect_with(username: Option<&str>, password: Option<&[u8]>) -> ConnectPacket {
        ConnectPacket {
            client_id: Arc::from("cid"),
            clean_session: true,
            keep_alive: 60,
            username: username.map(Arc::from),
            password: password.map(|p| Zeroizing::new(p.to_vec())),
            will: None,
        }
    }

    #[tokio::test]
    async fn single_tenant_round_trip() {
        let phc = make_phc(b"hunter2", b"s0", 1000);
        let json = format!(r#"{{"users":{{"alice":{{"password":"{}"}}}}}}"#, phc);
        let auth = JsonAuthenticator::from_str(&json).unwrap();
        let connect = connect_with(Some("alice"), Some(b"hunter2"));
        let result = auth.authenticate(None, &connect, None).await;
        assert!(result.accepted);
    }

    #[tokio::test]
    async fn wrong_password_rejected_with_bad_username_or_password_code() {
        let phc = make_phc(b"hunter2", b"s0", 1000);
        let json = format!(r#"{{"users":{{"alice":{{"password":"{}"}}}}}}"#, phc);
        let auth = JsonAuthenticator::from_str(&json).unwrap();
        let connect = connect_with(Some("alice"), Some(b"WRONG"));
        let result = auth.authenticate(None, &connect, None).await;
        assert!(!result.accepted);
        assert_eq!(result.return_code, ConnackReturnCode::BadUsernameOrPassword);
    }

    #[tokio::test]
    async fn unknown_user_rejected() {
        let auth = JsonAuthenticator::from_str(r#"{"users":{}}"#).unwrap();
        let connect = connect_with(Some("ghost"), Some(b"x"));
        let result = auth.authenticate(None, &connect, None).await;
        assert!(!result.accepted);
        assert_eq!(result.return_code, ConnackReturnCode::BadUsernameOrPassword);
    }

    #[tokio::test]
    async fn missing_username_rejected() {
        let auth = JsonAuthenticator::from_str(r#"{"users":{}}"#).unwrap();
        let connect = connect_with(None, Some(b"x"));
        let result = auth.authenticate(None, &connect, None).await;
        assert!(!result.accepted);
    }

    /// Mock verifier that counts invocations and reports the hash strings
    /// it saw. Lets us assert the dummy-hash path executes on every reject
    /// scenario so timing is uniform (F3).
    struct CountingVerifier {
        calls: std::sync::Mutex<Vec<String>>,
        accept_match: String,
    }

    impl CountingVerifier {
        fn new(accept_match: impl Into<String>) -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                accept_match: accept_match.into(),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl PasswordVerifier for CountingVerifier {
        fn verify(&self, hash: &str, _password: &[u8]) -> bool {
            self.calls.lock().unwrap().push(hash.to_string());
            hash == self.accept_match
        }
    }

    #[tokio::test]
    async fn verifier_runs_on_every_reject_path_for_uniform_timing() {
        let real_hash = "$pbkdf2-sha512$rounds=1$AA$BB"; // ignored value
        let json = format!(r#"{{"users":{{"alice":{{"password":"{real_hash}"}}}}}}"#);
        let counter = Arc::new(CountingVerifier::new(real_hash));
        let auth = JsonAuthenticator::from_str(&json)
            .unwrap()
            .with_verifier(counter.clone());

        // 1) Known user + correct password → accept (real hash used).
        let r = auth
            .authenticate(None, &connect_with(Some("alice"), Some(b"pw")), None)
            .await;
        assert!(r.accepted);

        // 2) Known user + wrong password → reject (real hash used).
        // Our mock accepts only when shown the exact real_hash, so any other
        // input fails. Tweak the verifier to take password into account would
        // require more plumbing — for the timing-uniformity property the hash
        // strings seen are what matters.
        let bad_verifier = Arc::new(CountingVerifier::new("never-matches"));
        let auth2 = JsonAuthenticator::from_str(&json)
            .unwrap()
            .with_verifier(bad_verifier.clone());
        let r = auth2
            .authenticate(None, &connect_with(Some("alice"), Some(b"wrong")), None)
            .await;
        assert!(!r.accepted);

        // 3) Unknown user → reject; dummy hash MUST be exercised.
        let r = auth2
            .authenticate(None, &connect_with(Some("ghost"), Some(b"pw")), None)
            .await;
        assert!(!r.accepted);

        // 4) Missing username → reject; dummy hash MUST be exercised.
        let r = auth2
            .authenticate(None, &connect_with(None, Some(b"pw")), None)
            .await;
        assert!(!r.accepted);

        // 5) Missing password → reject; dummy hash MUST be exercised.
        let r = auth2
            .authenticate(None, &connect_with(Some("alice"), None), None)
            .await;
        assert!(!r.accepted);

        // Per-call accounting on the second (reject-only) verifier:
        // 4 reject calls × 1 verify each = 4 total. None may be skipped.
        // This is the core F3 invariant — uniform CPU on every reject.
        let bad_calls = bad_verifier.calls();
        assert_eq!(
            bad_calls.len(),
            4,
            "every reject path must invoke verify exactly once for F3, saw {bad_calls:?}"
        );
        // Lookup-miss paths (unknown user, missing username) MUST verify
        // against the dummy. Missing-password against a known user falls
        // through to the real hash (which is fine — same wall-clock cost).
        let dummy_count = bad_calls
            .iter()
            .filter(|h| h.starts_with("$pbkdf2-sha512$rounds=10000$"))
            .count();
        assert_eq!(
            dummy_count, 2,
            "unknown-user + missing-username must verify against the dummy, \
             saw hashes: {bad_calls:?}"
        );
    }

    #[tokio::test]
    async fn multi_tenant_lookup_scoped_correctly() {
        let phc_a = make_phc(b"alpha-pw", b"sa", 1000);
        let phc_b = make_phc(b"beta-pw", b"sb", 1000);
        let json = format!(
            r#"{{
                "tenants": {{
                    "ta": {{"users": {{"alice": {{"password": "{phc_a}"}}}}}},
                    "tb": {{"users": {{"alice": {{"password": "{phc_b}"}}}}}}
                }}
            }}"#
        );
        let auth = JsonAuthenticator::from_str(&json).unwrap();

        // ta + alpha-pw → OK
        let ta: TenantId = Arc::from("ta");
        let connect = connect_with(Some("alice"), Some(b"alpha-pw"));
        assert!(auth.authenticate(Some(&ta), &connect, None).await.accepted);

        // tb + alpha-pw → reject (wrong tenant's password)
        let tb: TenantId = Arc::from("tb");
        assert!(!auth.authenticate(Some(&tb), &connect, None).await.accepted);

        // Unknown tenant → reject
        let tc: TenantId = Arc::from("does-not-exist");
        assert!(!auth.authenticate(Some(&tc), &connect, None).await.accepted);
    }

    /// G4 regression: `with_snapshot` MUST auto-pick the modal `rounds`
    /// from the snapshot's real users so the dummy hash burns the same
    /// CPU as the unknown-user verify (so T3 in SAFETY_PROOF holds even
    /// without an explicit `with_dummy_rounds` call).
    #[test]
    fn detect_modal_rounds_picks_majority() {
        // 3 users at rounds=5000, 1 user at rounds=12000 → modal = 5000.
        let phc1 = make_phc(b"pw1", b"s1", 5000);
        let phc2 = make_phc(b"pw2", b"s2", 5000);
        let phc3 = make_phc(b"pw3", b"s3", 5000);
        let phc4 = make_phc(b"pw4", b"s4", 12000);
        let json = format!(
            r#"{{"users": {{
                "a": {{"password": "{phc1}"}},
                "b": {{"password": "{phc2}"}},
                "c": {{"password": "{phc3}"}},
                "d": {{"password": "{phc4}"}}
            }}}}"#
        );
        let snapshot = Value::from_json(&json).unwrap();
        assert_eq!(detect_modal_rounds(&snapshot), Some(5000));
    }

    #[test]
    fn detect_modal_rounds_handles_multi_tenant() {
        let phc_a = make_phc(b"pw", b"s", 7000);
        let phc_b = make_phc(b"pw", b"s", 7000);
        let json = format!(
            r#"{{"tenants": {{
                "ta": {{"users": {{"a": {{"password": "{phc_a}"}}}}}},
                "tb": {{"users": {{"b": {{"password": "{phc_b}"}}}}}}
            }}}}"#
        );
        let snapshot = Value::from_json(&json).unwrap();
        assert_eq!(detect_modal_rounds(&snapshot), Some(7000));
    }

    #[test]
    fn detect_modal_rounds_empty_falls_back() {
        let snapshot = Value::from_json("{}").unwrap();
        assert_eq!(detect_modal_rounds(&snapshot), None);
    }

    /// U4 strict mode (Option B): uniform rounds across all users → Ok.
    #[test]
    fn strict_from_str_accepts_uniform_rounds() {
        let phc_a = make_phc(b"pwa", b"sa", 7777);
        let phc_b = make_phc(b"pwb", b"sb", 7777);
        let json = format!(
            r#"{{"users": {{
                "alice": {{"password": "{phc_a}"}},
                "bob": {{"password": "{phc_b}"}}
            }}}}"#
        );
        let auth = JsonAuthenticator::from_str_strict(&json).expect("uniform rounds accepted");
        // The dummy hash MUST encode the same `rounds` value so an
        // unknown-user verify has the same PBKDF2 cost.
        assert!(auth.dummy_hash.contains("rounds=7777"));
    }

    /// U4 strict mode: mixed rounds → Err (with informative message).
    #[test]
    fn strict_from_str_rejects_mixed_rounds() {
        let phc_a = make_phc(b"pwa", b"sa", 5000);
        let phc_b = make_phc(b"pwb", b"sb", 12000);
        let json = format!(
            r#"{{"users": {{
                "alice": {{"password": "{phc_a}"}},
                "bob": {{"password": "{phc_b}"}}
            }}}}"#
        );
        let err = match JsonAuthenticator::from_str_strict(&json) {
            Err(e) => e,
            Ok(_) => panic!("strict mode should reject"),
        };
        assert!(
            err.contains("distinct PBKDF2") && err.contains("rounds"),
            "expected strict-mode mixed-rounds error, got {err}"
        );
    }

    /// U4 strict mode: empty snapshot → Err (no PBKDF2 users to pin to).
    #[test]
    fn strict_from_str_rejects_empty_snapshot() {
        let err = match JsonAuthenticator::from_str_strict("{}") {
            Err(e) => e,
            Ok(_) => panic!("strict mode should reject empty snapshot"),
        };
        assert!(err.contains("no PBKDF2 users"));
    }

    /// SAFETY_PROOF v5 §7 F2 regression: the non-strict `from_str` path
    /// must ALSO reject mixed-rounds snapshots (it was previously a
    /// warn-and-continue path that fell back to modal rounds and left
    /// non-modal users timing-distinguishable).
    #[test]
    fn from_str_rejects_mixed_rounds_fail_closed() {
        let phc_a = make_phc(b"pwa", b"sa", 5000);
        let phc_b = make_phc(b"pwb", b"sb", 12000);
        let json = format!(
            r#"{{"users": {{
                "alice": {{"password": "{phc_a}"}},
                "bob": {{"password": "{phc_b}"}}
            }}}}"#
        );
        let err = match JsonAuthenticator::from_str(&json) {
            Err(e) => e,
            Ok(_) => panic!("from_str must fail-closed on mixed rounds (F2)"),
        };
        assert!(
            err.contains("distinct PBKDF2") && err.contains("rounds"),
            "expected F2 fail-closed mixed-rounds error, got {err}"
        );
    }

    /// F2 regression: empty / all-bcrypt snapshots STILL load through
    /// `from_str` (only `from_str_strict` rejects those). The reject is
    /// scoped to the actual timing-leak case: more-than-one PBKDF2 round.
    #[test]
    fn from_str_accepts_empty_snapshot_under_f2() {
        let auth = JsonAuthenticator::from_str(r#"{"users":{}}"#)
            .expect("empty snapshot is operational, F2 only rejects mixed rounds");
        // dummy must still encode the DEFAULT_DUMMY_ROUNDS fallback
        // so timing-equality with the unknown-user path holds.
        assert!(auth.dummy_hash.contains("rounds="));
    }
}
