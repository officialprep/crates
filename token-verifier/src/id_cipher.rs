use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::TokenError;

const NONCE_LEN: usize = 24;

type HmacSha256 = Hmac<Sha256>;

/// Encrypts the token subject (user id) so that decoding a token's payload reveals only
/// ciphertext, never the real id, to anyone without this key. The outer PASETO signature still
/// covers this ciphertext, so tampering is still detected without needing this key.
///
/// The nonce is derived deterministically from the id itself (via a domain-separated HMAC
/// subkey, not the encryption key directly) rather than generated randomly: the same id always
/// produces the same ciphertext under a given key. This is required, not just a nicety —
/// downstream services key all of a user's data off this value as if it were a stable identity,
/// so a random nonce would silently orphan a user's data on every token re-issuance. Determinism
/// doesn't weaken the AEAD's nonce-uniqueness requirement, since it only guarantees repeats for
/// the *same* id — different ids are still independent, HMAC-derived nonces.
pub struct TokenIdCipher {
    cipher: XChaCha20Poly1305,
    nonce_key: [u8; 32],
}

impl TokenIdCipher {
    pub fn new(key: [u8; 32]) -> Self {
        let mut mac: HmacSha256 =
            Mac::new_from_slice(&key).expect("HMAC-SHA256 accepts any key length");
        mac.update(b"token-id-cipher:nonce-derivation:v1");
        let nonce_key: [u8; 32] = mac.finalize().into_bytes().into();

        Self {
            cipher: XChaCha20Poly1305::new((&key).into()),
            nonce_key,
        }
    }

    fn derive_nonce(&self, id: Uuid) -> [u8; NONCE_LEN] {
        let mut mac: HmacSha256 = Mac::new_from_slice(&self.nonce_key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(id.as_bytes());
        let digest = mac.finalize().into_bytes();

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&digest[..NONCE_LEN]);
        nonce
    }

    pub fn encrypt(&self, id: Uuid) -> Result<String, TokenError> {
        let nonce_bytes = self.derive_nonce(id);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, id.as_bytes().as_slice())
            .map_err(|_| TokenError::Issue("failed to encrypt subject".to_string()))?;

        let mut payload = nonce_bytes.to_vec();
        payload.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(payload))
    }

    pub fn decrypt(&self, encoded: &str) -> Result<Uuid, TokenError> {
        let payload = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|err| TokenError::Verify(format!("malformed subject: {err}")))?;
        if payload.len() <= NONCE_LEN {
            return Err(TokenError::Verify("subject too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = payload.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| TokenError::Verify("failed to decrypt subject".to_string()))?;

        Uuid::from_slice(&plaintext).map_err(|err| TokenError::Verify(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn round_trips() {
        let cipher = TokenIdCipher::new(key(1));
        let id = Uuid::now_v7();

        let encrypted = cipher.encrypt(id).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(id, decrypted);
    }

    #[test]
    fn same_id_produces_identical_ciphertext() {
        let cipher = TokenIdCipher::new(key(1));
        let id = Uuid::now_v7();

        let first = cipher.encrypt(id).unwrap();
        let second = cipher.encrypt(id).unwrap();

        assert_eq!(first, second, "encryption must be deterministic per id");
    }

    #[test]
    fn different_ids_produce_different_ciphertext() {
        let cipher = TokenIdCipher::new(key(1));

        let a = cipher.encrypt(Uuid::now_v7()).unwrap();
        let b = cipher.encrypt(Uuid::now_v7()).unwrap();

        assert_ne!(a, b);
    }

    #[test]
    fn different_keys_produce_different_ciphertext_for_same_id() {
        let id = Uuid::now_v7();

        let under_key_one = TokenIdCipher::new(key(1)).encrypt(id).unwrap();
        let under_key_two = TokenIdCipher::new(key(2)).encrypt(id).unwrap();

        assert_ne!(under_key_one, under_key_two);
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let cipher = TokenIdCipher::new(key(1));
        let mut encrypted = cipher.encrypt(Uuid::now_v7()).unwrap();
        encrypted.replace_range(0..1, if encrypted.starts_with('A') { "B" } else { "A" });

        assert!(cipher.decrypt(&encrypted).is_err());
    }
}
