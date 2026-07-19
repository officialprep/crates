use std::collections::HashMap;
use std::sync::Arc;

use rand_core::RngCore;
use rusty_paseto::prelude::{Footer, Key, PasetoAsymmetricPrivateKey, PasetoBuilder, Public, V4};
use token_verifier::{
    ImplTokenVerifierPaseto, PasetoKeyRing, TokenIdCipherRing, TokenType, TokenVerifier,
};
use uuid::Uuid;

fn generate_key() -> Key<64> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    Key::<64>::from(signing_key.to_keypair_bytes())
}

fn generate_cipher_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut key);
    key
}

fn single_cipher_ring(cid: &str, key: [u8; 32]) -> Arc<TokenIdCipherRing> {
    let mut keys = HashMap::new();
    keys.insert(cid.to_string(), key);
    Arc::new(TokenIdCipherRing::new(cid.to_string(), keys))
}

fn issue_token(
    key: &Key<64>,
    kid: &str,
    sub: Uuid,
    typ: &str,
    id_cipher_ring: &TokenIdCipherRing,
) -> String {
    let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::try_from(key.as_slice()).unwrap();
    let footer = serde_json::json!({ "kid": kid }).to_string();
    let encrypted_sub = id_cipher_ring.active_cipher().encrypt(sub).unwrap();
    let sub_claim = format!("{}.{}", id_cipher_ring.active_cid(), encrypted_sub);
    PasetoBuilder::<V4, Public>::default()
        .subject(&sub_claim)
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
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let verifier = ImplTokenVerifierPaseto::new(ring, id_cipher_ring.clone());

    let sub = Uuid::now_v7();
    let token = issue_token(&key, "v1", sub, "access", &id_cipher_ring);

    let claims = verifier.verify(&token).expect("token should verify");
    assert_eq!(claims.sub, sub);
    assert_eq!(claims.token_type, TokenType::Access);
}

#[test]
fn verifies_a_token_with_the_v4_public_prefix_stripped() {
    let key = generate_key();
    let mut keys = HashMap::new();
    keys.insert("v1".to_string(), key.clone());
    let ring = Arc::new(PasetoKeyRing::new("v1".to_string(), keys));
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let verifier = ImplTokenVerifierPaseto::new(ring, id_cipher_ring.clone());

    let token = issue_token(&key, "v1", Uuid::now_v7(), "refresh", &id_cipher_ring);
    let trimmed = token.strip_prefix("v4.public.").unwrap();

    let claims = verifier.verify(trimmed).expect("prefix-stripped token should still verify");
    assert_eq!(claims.token_type, TokenType::Refresh);
}

#[test]
fn rejects_a_token_signed_by_an_unknown_key_id() {
    let signing_key = generate_key();
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let token = issue_token(&signing_key, "v1", Uuid::now_v7(), "access", &id_cipher_ring);

    let verifying_ring = Arc::new(PasetoKeyRing::new(
        "v2".to_string(),
        HashMap::from([("v2".to_string(), generate_key())]),
    ));
    let verifier = ImplTokenVerifierPaseto::new(verifying_ring, id_cipher_ring);

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
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let verifier = ImplTokenVerifierPaseto::new(ring, id_cipher_ring.clone());

    let old_token = issue_token(&key_v1, "v1", Uuid::now_v7(), "access", &id_cipher_ring);
    verifier.verify(&old_token).expect("token signed with a retired key must still verify");
}

#[test]
fn old_cipher_key_tokens_still_verify_after_cipher_rotation() {
    let key = generate_key();
    let mut signing_keys = HashMap::new();
    signing_keys.insert("v1".to_string(), key.clone());
    let signing_ring = Arc::new(PasetoKeyRing::new("v1".to_string(), signing_keys));

    let cid_old = "c1";
    let cid_new = "c2";
    let mut cipher_keys = HashMap::new();
    cipher_keys.insert(cid_old.to_string(), generate_cipher_key());
    let ring_before_rotation = Arc::new(TokenIdCipherRing::new(cid_old.to_string(), cipher_keys.clone()));

    let sub = Uuid::now_v7();
    let old_token = issue_token(&key, "v1", sub, "access", &ring_before_rotation);

    cipher_keys.insert(cid_new.to_string(), generate_cipher_key());
    let ring_after_rotation = Arc::new(TokenIdCipherRing::new(cid_new.to_string(), cipher_keys));

    let new_token = issue_token(&key, "v1", sub, "access", &ring_after_rotation);
    assert!(new_token != old_token);

    let verifier = ImplTokenVerifierPaseto::new(signing_ring, ring_after_rotation);

    let old_claims = verifier
        .verify(&old_token)
        .expect("token encrypted with a retired cipher key must still verify");
    assert_eq!(old_claims.sub, sub);

    let new_claims = verifier
        .verify(&new_token)
        .expect("token encrypted with the new active cipher key must verify");
    assert_eq!(new_claims.sub, sub);
}

#[test]
fn rejects_a_token_with_an_unknown_cipher_id() {
    let key = generate_key();
    let mut signing_keys = HashMap::new();
    signing_keys.insert("v1".to_string(), key.clone());
    let signing_ring = Arc::new(PasetoKeyRing::new("v1".to_string(), signing_keys));

    let issuing_ring = single_cipher_ring("c1", generate_cipher_key());
    let token = issue_token(&key, "v1", Uuid::now_v7(), "access", &issuing_ring);

    let verifying_ring = single_cipher_ring("c2", generate_cipher_key());
    let verifier = ImplTokenVerifierPaseto::new(signing_ring, verifying_ring);

    assert!(verifier.verify(&token).is_err());
}
