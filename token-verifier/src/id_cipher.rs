use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use uuid::Uuid;

use crate::error::TokenError;

const NONCE_LEN: usize = 24;

/// Encrypts the token subject (user id) so that decoding a token's payload
/// reveals only ciphertext, never the real id. The outer PASETO signature
/// still covers this ciphertext, so tampering is still detected without
/// needing this key.
pub struct TokenIdCipher {
    cipher: XChaCha20Poly1305,
}

impl TokenIdCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new((&key).into()),
        }
    }

    pub fn encrypt(&self, id: Uuid) -> Result<String, TokenError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
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
