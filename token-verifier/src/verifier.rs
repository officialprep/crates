use std::sync::Arc;

use rusty_paseto::prelude::{Footer, Key, PasetoAsymmetricPublicKey, PasetoParser, Public, UntrustedToken, V4};
use uuid::Uuid;

use crate::error::TokenError;
use crate::key_ring::PasetoKeyRing;
use crate::model::{ModelClaims, TokenType};
use crate::V4_PUBLIC_PREFIX;

pub trait TokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<ModelClaims, TokenError>;
}

pub struct ImplTokenVerifierPaseto {
    key_ring: Arc<PasetoKeyRing>,
}

impl ImplTokenVerifierPaseto {
    pub fn new(key_ring: Arc<PasetoKeyRing>) -> Self {
        Self { key_ring }
    }
}

impl TokenVerifier for ImplTokenVerifierPaseto {
    fn verify(&self, token: &str) -> Result<ModelClaims, TokenError> {
        let token = if token.starts_with(V4_PUBLIC_PREFIX) {
            token.to_string()
        } else {
            format!("{V4_PUBLIC_PREFIX}{token}")
        };
        let token = token.as_str();

        let untrusted = UntrustedToken::try_parse(token).map_err(|err| TokenError::Verify(err.to_string()))?;
        let footer_str = untrusted
            .footer_str()
            .map_err(|err| TokenError::Verify(err.to_string()))?
            .ok_or_else(|| TokenError::Verify("token missing key id footer".to_string()))?;
        let footer_value: serde_json::Value = serde_json::from_str(&footer_str)
            .map_err(|err| TokenError::Verify(format!("malformed footer: {err}")))?;
        let kid = footer_value["kid"]
            .as_str()
            .ok_or_else(|| TokenError::Verify("footer missing kid".to_string()))?;

        let signing_key = self
            .key_ring
            .key_for(kid)
            .ok_or_else(|| TokenError::Verify(format!("unknown key id: {kid}")))?;
        let public_key_bytes: [u8; 32] = signing_key.as_slice()[32..]
            .try_into()
            .map_err(|_| TokenError::Verify("malformed stored key".to_string()))?;
        let public_key_bytes = Key::<32>::from(public_key_bytes);
        let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key_bytes);

        let claims_json = PasetoParser::<V4, Public>::default()
            .set_footer(Footer::from(footer_str.as_str()))
            .parse(token, &public_key)
            .map_err(|err| TokenError::Verify(err.to_string()))?;

        let sub = claims_json["sub"]
            .as_str()
            .ok_or_else(|| TokenError::Verify("missing sub claim".to_string()))?;
        let email = claims_json["email"]
            .as_str()
            .ok_or_else(|| TokenError::Verify("missing email claim".to_string()))?;
        let typ = claims_json["typ"]
            .as_str()
            .ok_or_else(|| TokenError::Verify("missing typ claim".to_string()))?;
        let sub = Uuid::parse_str(sub).map_err(|err| TokenError::Verify(err.to_string()))?;
        let token_type =
            TokenType::parse(typ).ok_or_else(|| TokenError::Verify(format!("unknown typ claim: {typ}")))?;

        Ok(ModelClaims {
            sub,
            email: email.to_string(),
            token_type,
        })
    }
}
