use std::collections::HashMap;

use rusty_paseto::prelude::Key;

pub struct PasetoKeyRing {
    active_kid: String,
    keys: HashMap<String, Key<64>>,
}

impl PasetoKeyRing {
    pub fn new(active_kid: String, keys: HashMap<String, Key<64>>) -> Self {
        Self { active_kid, keys }
    }

    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    pub fn active_key(&self) -> &Key<64> {
        self.keys
            .get(&self.active_kid)
            .expect("active_kid must be present in keys")
    }

    pub fn key_for(&self, kid: &str) -> Option<&Key<64>> {
        self.keys.get(kid)
    }
}
