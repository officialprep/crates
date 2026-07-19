use std::collections::HashMap;
use std::sync::Arc;

use rusty_paseto::prelude::{Footer, Key, PasetoAsymmetricPrivateKey, PasetoBuilder, Public, V4};
use token_verifier::{ImplTokenVerifierPaseto, PasetoKeyRing, TokenType, TokenVerifier};
use uuid::Uuid;

fn generate_key() -> Key<64> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    Key::<64>::from(signing_key.to_keypair_bytes())
}

fn issue_token(key: &Key<64>, kid: &str, sub: Uuid, email: &str, typ: &str) -> String {
    let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::try_from(key.as_slice()).unwrap();
    let footer = serde_json::json!({ "kid": kid }).to_string();
    PasetoBuilder::<V4, Public>::default()
        .subject(&sub.to_string())
        .claim("email", email)
        .unwrap()
        .claim("typ", typ)
        .unwrap()
        .set_footer(Footer::from(footer.as_str()))
        .build(&private_key)
        .unwrap()
}

#[test]
fn verifies_a_correctly_signed_access_token() {
    let key = generate_key();
    let mut keys = HashMap::new();
    keys.insert("v1".to_string(), key.clone());
    let ring = Arc::new(PasetoKeyRing::new("v1".to_string(), keys));
    let verifier = ImplTokenVerifierPaseto::new(ring);

    let sub = Uuid::now_v7();
    let token = issue_token(&key, "v1", sub, "user@example.com", "access");

    let claims = verifier.verify(&token).expect("token should verify");
    assert_eq!(claims.sub, sub);
    assert_eq!(claims.email, "user@example.com");
    assert_eq!(claims.token_type, TokenType::Access);
}

#[test]
fn verifies_a_token_with_the_v4_public_prefix_stripped() {
    let key = generate_key();
    let mut keys = HashMap::new();
    keys.insert("v1".to_string(), key.clone());
    let ring = Arc::new(PasetoKeyRing::new("v1".to_string(), keys));
    let verifier = ImplTokenVerifierPaseto::new(ring);

    let token = issue_token(&key, "v1", Uuid::now_v7(), "user@example.com", "refresh");
    let trimmed = token.strip_prefix("v4.public.").unwrap();

    let claims = verifier.verify(trimmed).expect("prefix-stripped token should still verify");
    assert_eq!(claims.token_type, TokenType::Refresh);
}

#[test]
fn rejects_a_token_signed_by_an_unknown_key_id() {
    let signing_key = generate_key();
    let token = issue_token(&signing_key, "v1", Uuid::now_v7(), "user@example.com", "access");

    let verifying_ring = Arc::new(PasetoKeyRing::new(
        "v2".to_string(),
        HashMap::from([("v2".to_string(), generate_key())]),
    ));
    let verifier = ImplTokenVerifierPaseto::new(verifying_ring);

    assert!(verifier.verify(&token).is_err());
}

#[test]
fn old_key_tokens_still_verify_after_rotation() {
    let key_v1 = generate_key();
    let key_v2 = generate_key();
    let mut keys = HashMap::new();
    keys.insert("v1".to_string(), key_v1.clone());
    keys.insert("v2".to_string(), key_v2.clone());
    let ring = Arc::new(PasetoKeyRing::new("v2".to_string(), keys));
    let verifier = ImplTokenVerifierPaseto::new(ring);

    let old_token = issue_token(&key_v1, "v1", Uuid::now_v7(), "user@example.com", "access");
    verifier.verify(&old_token).expect("token signed with a retired key must still verify");
}
