//! Password hashing schemes and PHC string parsing.
//!
//! Canonical format is PHC (`$pbkdf2-sha512$rounds=N$<salt-b64>$<hash-b64>`).
//! `mosquitto_passwd` `$7$` format is **not** parsed natively — convert via
//! the future import tool ([`crate::auth`] doc + task #23).
//!
//! All comparisons use `subtle::ConstantTimeEq` to avoid timing oracles.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

// ============================================================================
// PasswordVerifier trait
// ============================================================================

/// Verifies a plaintext password against a stored PHC-format hash string.
pub trait PasswordVerifier: Send + Sync + 'static {
    fn verify(&self, hash: &str, password: &[u8]) -> bool;
}

// ============================================================================
// PHC string model
// ============================================================================

/// Parsed PHC string. Surfaces the scheme + per-scheme parameters in a form
/// the verifier dispatch can switch on.
///
/// `Debug` is hand-written (SAFETY_PROOF G3) — raw salt + hash bytes are
/// printed only as redacted length markers so accidental log/trace output
/// cannot feed an offline brute-forcer.
#[derive(Clone, PartialEq, Eq)]
pub enum PasswordHash {
    /// `$pbkdf2-sha512$rounds=N$salt$hash` (PHC) — base64 salt/hash.
    Pbkdf2Sha512 {
        rounds: u32,
        salt: Vec<u8>,
        hash: Vec<u8>,
    },
    /// `$2b$...` / `$2y$...` bcrypt — passed through to the `bcrypt` crate
    /// when the `auth-bcrypt` feature is on.
    #[cfg(feature = "auth-bcrypt")]
    Bcrypt(String),
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pbkdf2Sha512 { rounds, salt, hash } => f
                .debug_struct("Pbkdf2Sha512")
                .field("rounds", rounds)
                .field("salt", &format_args!("<{} bytes>", salt.len()))
                .field("hash", &format_args!("<redacted: {} bytes>", hash.len()))
                .finish(),
            #[cfg(feature = "auth-bcrypt")]
            Self::Bcrypt(_) => f
                .debug_struct("Bcrypt")
                .field("phc", &"<redacted>")
                .finish(),
        }
    }
}

impl PasswordHash {
    /// Parse a PHC-format hash string. Returns `None` for unrecognized or
    /// malformed input — callers MUST treat a `None` here as a verification
    /// failure (never as "accept" or "skip").
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix('$')?;
        let scheme_end = rest.find('$')?;
        let scheme = &rest[..scheme_end];
        let rest = &rest[scheme_end + 1..];

        match scheme {
            "pbkdf2-sha512" => parse_pbkdf2_sha512(rest),
            #[cfg(feature = "auth-bcrypt")]
            "2b" | "2y" | "2a" => Some(PasswordHash::Bcrypt(s.to_owned())),
            _ => None,
        }
    }
}

fn parse_pbkdf2_sha512(body: &str) -> Option<PasswordHash> {
    // `rounds=N$salt$hash` — base64 (standard alphabet, no padding).
    let mut parts = body.splitn(3, '$');
    let rounds_kv = parts.next()?;
    let salt_b64 = parts.next()?;
    let hash_b64 = parts.next()?;

    let rounds: u32 = rounds_kv.strip_prefix("rounds=")?.parse().ok()?;
    if rounds == 0 {
        return None;
    }
    let salt = decode_b64_any(salt_b64)?;
    let hash = decode_b64_any(hash_b64)?;
    if salt.is_empty() || hash.is_empty() {
        return None;
    }
    Some(PasswordHash::Pbkdf2Sha512 { rounds, salt, hash })
}

/// Try standard base64 first, then URL-safe; tolerate missing padding. PHC
/// strings sometimes omit padding (RFC 9106 §3.3), so we accept both.
fn decode_b64_any(s: &str) -> Option<Vec<u8>> {
    if let Ok(v) = general_purpose::STANDARD_NO_PAD.decode(s) {
        return Some(v);
    }
    if let Ok(v) = general_purpose::STANDARD.decode(s) {
        return Some(v);
    }
    if let Ok(v) = general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Some(v);
    }
    general_purpose::URL_SAFE.decode(s).ok()
}

// ============================================================================
// DefaultPasswordVerifier — dispatches by scheme
// ============================================================================

/// Stateless verifier supporting all PHC schemes the crate is built with.
/// PBKDF2-SHA512 is always available; bcrypt / sha512crypt require their
/// respective feature flags.
pub struct DefaultPasswordVerifier;

impl PasswordVerifier for DefaultPasswordVerifier {
    fn verify(&self, hash: &str, password: &[u8]) -> bool {
        verify_password(hash, password)
    }
}

/// Same as [`DefaultPasswordVerifier::verify`] but as a free function — handy
/// for one-shot checks without instantiating the verifier.
pub fn verify_password(hash: &str, password: &[u8]) -> bool {
    let Some(parsed) = PasswordHash::parse(hash) else {
        return false;
    };
    match parsed {
        PasswordHash::Pbkdf2Sha512 { rounds, salt, hash } => {
            verify_pbkdf2_sha512(password, &salt, rounds, &hash)
        }
        #[cfg(feature = "auth-bcrypt")]
        PasswordHash::Bcrypt(phc) => {
            bcrypt::verify(password, &phc).unwrap_or(false)
        }
    }
}

fn verify_pbkdf2_sha512(password: &[u8], salt: &[u8], rounds: u32, expected: &[u8]) -> bool {
    // F4 hardening: the derived key would otherwise sit on the heap until
    // dropped — `Zeroizing` wipes the buffer on scope exit so a coredump
    // or post-free read cannot recover it. Plaintext `password` here is a
    // borrow whose owner is `ConnectPacket.password: Bytes`; we wrap the
    // computed buffer only.
    let mut computed: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; expected.len()]);
    if pbkdf2::<Hmac<Sha512>>(password, salt, rounds, &mut computed).is_err() {
        return false;
    }
    computed.as_slice().ct_eq(expected).into()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a real PHC PBKDF2-SHA512 hash for known password.
    fn make_pbkdf2_phc(password: &[u8], salt: &[u8], rounds: u32) -> String {
        let mut hash = vec![0u8; 32];
        pbkdf2::<Hmac<Sha512>>(password, salt, rounds, &mut hash).unwrap();
        format!(
            "$pbkdf2-sha512$rounds={}${}${}",
            rounds,
            general_purpose::STANDARD_NO_PAD.encode(salt),
            general_purpose::STANDARD_NO_PAD.encode(&hash),
        )
    }

    #[test]
    fn pbkdf2_round_trip_verifies() {
        let phc = make_pbkdf2_phc(b"hunter2", b"saltsalt", 1000);
        assert!(verify_password(&phc, b"hunter2"));
    }

    #[test]
    fn pbkdf2_wrong_password_rejected() {
        let phc = make_pbkdf2_phc(b"hunter2", b"saltsalt", 1000);
        assert!(!verify_password(&phc, b"hunter3"));
    }

    #[test]
    fn pbkdf2_tampered_salt_rejected() {
        let phc = make_pbkdf2_phc(b"hunter2", b"saltsalt", 1000);
        // Swap salt segment with a different one (re-encode).
        let parts: Vec<&str> = phc.splitn(5, '$').collect();
        let bad_salt = general_purpose::STANDARD_NO_PAD.encode(b"different");
        let tampered = format!(
            "${}${}${}${}",
            parts[1], parts[2], bad_salt, parts[4],
        );
        assert!(!verify_password(&tampered, b"hunter2"));
    }

    #[test]
    fn malformed_phc_strings_rejected() {
        // Each of these should fail to parse and so fail to verify.
        for bad in [
            "",
            "$",
            "$pbkdf2-sha512$rounds=1000",
            "$pbkdf2-sha512$rounds=0$AAAA$BBBB",
            "$pbkdf2-sha512$rounds=notanumber$AAAA$BBBB",
            "$pbkdf2-sha512$rounds=1000$$BBBB",
            "$pbkdf2-sha512$rounds=1000$AAAA$",
            "$unknown-scheme$rounds=1$AAAA$BBBB",
            "plain-text-password",
        ] {
            assert!(
                !verify_password(bad, b"hunter2"),
                "should not verify: {bad:?}"
            );
        }
    }

    #[test]
    fn parse_extracts_canonical_form() {
        let phc = make_pbkdf2_phc(b"x", b"abcd", 42);
        let parsed = PasswordHash::parse(&phc).expect("parse");
        match parsed {
            PasswordHash::Pbkdf2Sha512 { rounds, salt, hash } => {
                assert_eq!(rounds, 42);
                assert_eq!(salt, b"abcd");
                assert_eq!(hash.len(), 32);
            }
            #[allow(unreachable_patterns)]
            other => panic!("expected Pbkdf2Sha512, got {other:?}"),
        }
    }

    /// SAFETY_PROOF G3 regression: `Debug` output MUST NOT contain raw
    /// salt or hash bytes, only length markers.
    #[test]
    fn debug_redacts_salt_and_hash_bytes() {
        let phc = PasswordHash::Pbkdf2Sha512 {
            rounds: 10_000,
            salt: b"super-secret-salt-bytes".to_vec(),
            hash: b"\xde\xad\xbe\xef\xca\xfeUNIQUE_HASH_TOKEN".to_vec(),
        };
        let rendered = format!("{phc:?}");
        assert!(
            !rendered.contains("super-secret-salt-bytes"),
            "salt bytes leaked into Debug: {rendered}"
        );
        assert!(
            !rendered.contains("UNIQUE_HASH_TOKEN"),
            "hash bytes leaked into Debug: {rendered}"
        );
        assert!(rendered.contains("rounds: 10000"));
        assert!(rendered.contains("<redacted:"));
    }
}
