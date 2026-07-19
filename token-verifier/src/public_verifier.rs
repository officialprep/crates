use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pasetors::claims::ClaimsValidationRules;
use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{public, Public};

use crate::error::TokenError;
use crate::id_cipher_ring::TokenIdCipherRing;
use crate::model::{ModelClaims, TokenType};
use crate::verifier::TokenVerifier;
use crate::V4_PUBLIC_PREFIX;

/// Verifies PASETO v4.public tokens using only the issuer's public key.
/// Unlike `ImplTokenVerifierPaseto`, which needs a `PasetoKeyRing` holding
/// the full keypair even to verify, this type can never sign a token —
/// only check one. Use this in any service that verifies tokens issued
/// elsewhere but never issues its own.
pub struct ImplTokenVerifierPasetoPublic {
    public_keys: HashMap<String, AsymmetricPublicKey<V4>>,
    id_cipher_ring: Arc<TokenIdCipherRing>,
}

impl ImplTokenVerifierPasetoPublic {
    pub fn new(public_keys: HashMap<String, AsymmetricPublicKey<V4>>, id_cipher_ring: Arc<TokenIdCipherRing>) -> Self {
        Self { public_keys, id_cipher_ring }
    }

    /// Builds a verifier straight from two env vars — `public_keys_var`
    /// (standard base64 `kid:key`, comma-separated) and `id_cipher_keys_var`
    /// (hex `cid:key`, comma-separated). Lets a service wire this up in one
    /// call instead of hand-rolling the same env-parsing loop every other
    /// verify-only service already needs. Panics loudly on misconfiguration
    /// rather than silently falling back to an unusable key.
    pub fn from_env(public_keys_var: &str, id_cipher_keys_var: &str) -> Self {
        let raw = std::env::var(public_keys_var).unwrap_or_else(|_| {
            panic!("{public_keys_var} must be set to the public half of the issuer's signing keys")
        });
        let public_keys = Self::parse_public_keys(public_keys_var, &raw);
        let id_cipher_ring = Arc::new(TokenIdCipherRing::from_env(id_cipher_keys_var));
        Self::new(public_keys, id_cipher_ring)
    }

    fn parse_public_keys(var_name: &str, raw: &str) -> HashMap<String, AsymmetricPublicKey<V4>> {
        let mut keys = HashMap::new();
        for entry in raw.split(',') {
            let (kid, base64_key) = entry
                .split_once(':')
                .unwrap_or_else(|| panic!("{var_name} entries must be `kid:base64key`, comma-separated"));
            let bytes = STANDARD
                .decode(base64_key)
                .unwrap_or_else(|_| panic!("{var_name} key must be valid standard base64"));
            let key = AsymmetricPublicKey::<V4>::from(&bytes)
                .unwrap_or_else(|_| panic!("{var_name} key must be a 32-byte Ed25519 public key, base64-encoded"));
            keys.insert(kid.to_string(), key);
        }

        if keys.is_empty() {
            panic!("{var_name} must contain at least one entry");
        }

        keys
    }
}

impl TokenVerifier for ImplTokenVerifierPasetoPublic {
    fn verify(&self, token: &str) -> Result<ModelClaims, TokenError> {
        let token = if token.starts_with(V4_PUBLIC_PREFIX) {
            token.to_string()
        } else {
            format!("{V4_PUBLIC_PREFIX}{token}")
        };

        let untrusted =
            UntrustedToken::<Public, V4>::try_from(token.as_str()).map_err(|err| TokenError::Verify(err.to_string()))?;
        let footer_value: serde_json::Value = serde_json::from_slice(untrusted.untrusted_footer())
            .map_err(|err| TokenError::Verify(format!("malformed footer: {err}")))?;
        let kid = footer_value["kid"]
            .as_str()
            .ok_or_else(|| TokenError::Verify("footer missing kid".to_string()))?;
        let public_key = self
            .public_keys
            .get(kid)
            .ok_or_else(|| TokenError::Verify(format!("unknown key id: {kid}")))?;

        let validation_rules = ClaimsValidationRules::new();
        let trusted = public::verify(public_key, &untrusted, &validation_rules, None, None)
            .map_err(|err| TokenError::Verify(err.to_string()))?;
        let claims = trusted
            .payload_claims()
            .expect("public::verify always populates payload_claims on success");

        let sub = claims
            .get_claim("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::Verify("missing sub claim".to_string()))?;
        let typ = claims
            .get_claim("typ")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenError::Verify("missing typ claim".to_string()))?;

        let (cid, ciphertext) = sub.split_once('.').ok_or_else(|| TokenError::Verify("malformed subject".to_string()))?;
        let cipher = self
            .id_cipher_ring
            .cipher_for(cid)
            .ok_or_else(|| TokenError::Verify(format!("unknown cipher id: {cid}")))?;
        let sub = cipher.decrypt(ciphertext)?;
        let token_type = TokenType::parse(typ).ok_or_else(|| TokenError::Verify(format!("unknown typ claim: {typ}")))?;

        Ok(ModelClaims { sub, token_type })
    }
}
