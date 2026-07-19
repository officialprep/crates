pub mod error;
pub mod id_cipher;
pub mod id_cipher_ring;
pub mod key_ring;
pub mod model;
pub mod verifier;

pub use error::TokenError;
pub use id_cipher::TokenIdCipher;
pub use id_cipher_ring::TokenIdCipherRing;
pub use key_ring::PasetoKeyRing;
pub use model::{ModelClaims, TokenType};
pub use verifier::{ImplTokenVerifierPaseto, TokenVerifier};

pub const V4_PUBLIC_PREFIX: &str = "v4.public.";

pub fn for_client(token: &str) -> String {
    token.strip_prefix(V4_PUBLIC_PREFIX).unwrap_or(token).to_string()
}
