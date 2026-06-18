//! Stage A P2.C — broker-side authentication primitives.
//!
//! - [`password`] — `PasswordVerifier` trait, PHC string parsing, PBKDF2-SHA512
//!   default verifier, optional `bcrypt` impl (feature-gated `auth-bcrypt`).
//!   `sha512-crypt` (`$6$...`) is deferred — see Cargo.toml note.
//! - [`json`] — `JsonAuthenticator` backed by an akari JSON snapshot with the
//!   layout `tenants.<id>.users.<name>.password` (or `users.<name>.password`
//!   in single-tenant deployments).

pub mod acl;
pub mod json;
pub mod password;

pub use acl::JsonAclChecker;
pub use json::JsonAuthenticator;
pub use password::{DefaultPasswordVerifier, PasswordHash, PasswordVerifier, verify_password};
