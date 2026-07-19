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

    /// Parses `cid:hex32key` entries, comma-separated, first entry active —
    /// the convention every service using this crate sets `TOKEN_ID_CIPHER_KEYS`
    /// to, so consumers don't each hand-roll the same parsing loop.
    pub fn parse(raw: &str) -> Self {
        let mut keys = HashMap::new();
        let mut active_cid = None;
        for entry in raw.split(',') {
            let (cid, hex_key) = entry
                .split_once(':')
                .expect("TOKEN_ID_CIPHER_KEYS entries must be `cid:hex64key`, comma-separated");
            let bytes = hex::decode(hex_key).expect("TOKEN_ID_CIPHER_KEYS key must be valid hex");
            let key: [u8; 32] = bytes
                .try_into()
                .expect("TOKEN_ID_CIPHER_KEYS key must be exactly 32 bytes (64 hex chars)");
            active_cid.get_or_insert_with(|| cid.to_string());
            keys.insert(cid.to_string(), key);
        }

        Self::new(
            active_cid.expect("TOKEN_ID_CIPHER_KEYS must contain at least one entry"),
            keys,
        )
    }

    /// Reads `var_name` from the environment and parses it via [`Self::parse`].
    pub fn from_env(var_name: &str) -> Self {
        let raw = std::env::var(var_name)
            .unwrap_or_else(|_| panic!("{var_name} must be set (needed to decrypt the token subject)"));
        Self::parse(&raw)
    }
}
