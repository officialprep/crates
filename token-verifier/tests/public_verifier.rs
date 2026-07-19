#![cfg(feature = "public-verify")]

use std::collections::HashMap;
use std::sync::Arc;

use pasetors::keys::AsymmetricPublicKey;
use pasetors::version4::V4 as PasetorsV4;
use rand_core::RngCore;
use rusty_paseto::prelude::{Footer, PasetoAsymmetricPrivateKey, PasetoBuilder, Public, V4};
use token_verifier::{ImplTokenVerifierPasetoPublic, TokenIdCipherRing, TokenType, TokenVerifier};
use uuid::Uuid;

fn generate_keypair() -> [u8; 64] {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    signing_key.to_keypair_bytes()
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

fn issue_token(keypair: &[u8; 64], kid: &str, sub: Uuid, typ: &str, id_cipher_ring: &TokenIdCipherRing) -> String {
    let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::try_from(keypair.as_slice()).unwrap();
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

fn public_key_map(kid: &str, keypair: &[u8; 64]) -> HashMap<String, AsymmetricPublicKey<PasetorsV4>> {
    let mut keys = HashMap::new();
    keys.insert(kid.to_string(), AsymmetricPublicKey::<PasetorsV4>::from(&keypair[32..]).unwrap());
    keys
}

#[test]
fn verifies_a_correctly_signed_access_token_with_only_the_public_key() {
    let keypair = generate_keypair();
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let verifier = ImplTokenVerifierPasetoPublic::new(public_key_map("v1", &keypair), id_cipher_ring.clone());

    let sub = Uuid::now_v7();
    let token = issue_token(&keypair, "v1", sub, "access", &id_cipher_ring);

    let claims = verifier.verify(&token).expect("token should verify");
    assert_eq!(claims.sub, sub);
    assert_eq!(claims.token_type, TokenType::Access);
}

#[test]
fn verifies_a_token_with_the_v4_public_prefix_stripped() {
    let keypair = generate_keypair();
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let verifier = ImplTokenVerifierPasetoPublic::new(public_key_map("v1", &keypair), id_cipher_ring.clone());

    let token = issue_token(&keypair, "v1", Uuid::now_v7(), "refresh", &id_cipher_ring);
    let trimmed = token.strip_prefix("v4.public.").unwrap();

    let claims = verifier.verify(trimmed).expect("prefix-stripped token should still verify");
    assert_eq!(claims.token_type, TokenType::Refresh);
}

#[test]
fn rejects_a_token_signed_by_an_unknown_key_id() {
    let signing_keypair = generate_keypair();
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let token = issue_token(&signing_keypair, "v1", Uuid::now_v7(), "access", &id_cipher_ring);

    let other_keypair = generate_keypair();
    let verifier = ImplTokenVerifierPasetoPublic::new(public_key_map("v2", &other_keypair), id_cipher_ring);

    assert!(verifier.verify(&token).is_err());
}

#[test]
fn rejects_a_token_tampered_after_signing() {
    let keypair = generate_keypair();
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let verifier = ImplTokenVerifierPasetoPublic::new(public_key_map("v1", &keypair), id_cipher_ring.clone());

    let token = issue_token(&keypair, "v1", Uuid::now_v7(), "access", &id_cipher_ring);
    let mut tampered = token.clone();
    tampered.push('x');

    assert!(verifier.verify(&tampered).is_err());
}

#[test]
fn old_key_tokens_still_verify_after_rotation() {
    let keypair_v1 = generate_keypair();
    let keypair_v2 = generate_keypair();
    let mut keys = public_key_map("v1", &keypair_v1);
    keys.extend(public_key_map("v2", &keypair_v2));
    let id_cipher_ring = single_cipher_ring("c1", generate_cipher_key());
    let verifier = ImplTokenVerifierPasetoPublic::new(keys, id_cipher_ring.clone());

    let old_token = issue_token(&keypair_v1, "v1", Uuid::now_v7(), "access", &id_cipher_ring);
    verifier.verify(&old_token).expect("token signed with a retired key must still verify");
}

#[test]
fn rejects_a_token_with_an_unknown_cipher_id() {
    let keypair = generate_keypair();
    let issuing_ring = single_cipher_ring("c1", generate_cipher_key());
    let token = issue_token(&keypair, "v1", Uuid::now_v7(), "access", &issuing_ring);

    let verifying_ring = single_cipher_ring("c2", generate_cipher_key());
    let verifier = ImplTokenVerifierPasetoPublic::new(public_key_map("v1", &keypair), verifying_ring);

    assert!(verifier.verify(&token).is_err());
}
