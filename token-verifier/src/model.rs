use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Refresh,
}

impl TokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenType::Access => "access",
            TokenType::Refresh => "refresh",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "access" => Some(TokenType::Access),
            "refresh" => Some(TokenType::Refresh),
            _ => None,
        }
    }
}

pub struct ModelClaims {
    pub sub: Uuid,
    pub email: String,
    pub token_type: TokenType,
}
