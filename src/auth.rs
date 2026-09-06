//! Tenant credential generation and verification. See `docs/DESIGN.md` §10.1.
//!
//! Two credential types: `pk_...` (public, embedded in a merchant's static site JS,
//! never authorizes anything) and `sk_...` (secret, resolves "which tenant" for every
//! `/api/v1/admin/tenant/*` route). The structural rule this module exists to support:
//! tenant identity for admin routes comes *only* from the `sk_` token, never from a
//! path parameter - see `Store::find_tenant_by_secret_token` in `store.rs`, which is
//! the only lookup admin auth is allowed to use.

use rand::Rng;
use sha2::{Digest, Sha256};

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn generate_public_key() -> String {
    format!("pk_{}", random_hex(24))
}

pub fn generate_secret_token() -> String {
    format!("sk_{}", random_hex(32))
}

/// A webhook's HMAC signing secret. Unlike `sk_`, this is stored reversibly (see
/// `webhooks.signing_secret` in the schema) since it's needed on every delivery, not
/// just checked once - "shown once" for this value is an API convention, not a
/// hashing guarantee.
pub fn generate_webhook_secret() -> String {
    format!("whsec_{}", random_hex(32))
}

/// SHA-256 hex digest of a raw `sk_...` token, for storage in
/// `tenants.secret_token_hash`. Not Argon2/bcrypt/scrypt on purpose - see module docs.
pub fn hash_secret_token(raw_token: &str) -> String {
    hex::encode(Sha256::digest(raw_token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_public_and_secret_keys_have_expected_prefixes_and_are_unique() {
        let pk1 = generate_public_key();
        let pk2 = generate_public_key();
        let sk1 = generate_secret_token();
        let sk2 = generate_secret_token();
        assert!(pk1.starts_with("pk_"));
        assert!(sk1.starts_with("sk_"));
        assert_ne!(pk1, pk2);
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn hash_is_deterministic_and_sensitive_to_every_bit() {
        let token = generate_secret_token();
        assert_eq!(hash_secret_token(&token), hash_secret_token(&token));

        // Flip the last character - a valid token with one bit different must hash
        // to something else entirely, and must never be treated as a prefix/partial
        // match by whatever compares against the stored hash.
        let mut flipped = token.clone();
        let last = flipped.pop().unwrap();
        let replacement = if last == 'a' { 'b' } else { 'a' };
        flipped.push(replacement);
        assert_ne!(hash_secret_token(&token), hash_secret_token(&flipped));
    }
}
