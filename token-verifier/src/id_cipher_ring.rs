use std::collections::HashMap;

use crate::id_cipher::TokenIdCipher;

pub struct TokenIdCipherRing {
    active_cid: String,
    ciphers: HashMap<String, TokenIdCipher>,
}

impl TokenIdCipherRing {
    pub fn new(active_cid: String, keys: HashMap<String, [u8; 32]>) -> Self {
        let ciphers = keys
            .into_iter()
            .map(|(cid, key)| (cid, TokenIdCipher::new(key)))
            .collect();
        Self { active_cid, ciphers }
    }

    pub fn active_cid(&self) -> &str {
        &self.active_cid
    }

    pub fn active_cipher(&self) -> &TokenIdCipher {
        self.ciphers
            .get(&self.active_cid)
            .expect("active_cid must be present in ciphers")
    }

    pub fn cipher_for(&self, cid: &str) -> Option<&TokenIdCipher> {
        self.ciphers.get(cid)
    }
}
