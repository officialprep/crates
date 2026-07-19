use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("failed to issue token: {0}")]
    Issue(String),
    #[error("failed to verify token: {0}")]
    Verify(String),
}
