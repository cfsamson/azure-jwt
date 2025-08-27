use crate::jwt;
use std::{error::Error, fmt};

// non_exhaustive:
// Allows ConnectionError variant to be conditional.
// Also allows variants to be added for control-flow reasons.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthErr {
    /// The auth is in an invalid state. For example, it might have attempted offline-validation
    /// without having set the public keys.
    InvalidState,
    /// The token is not valid in our context. For example, it might be missing a key-id.
    InvalidTokenState,
    /// The token did not match our expected values. For example, it might have provided a key-id
    /// that did not match any of the public keys. This may indicate public-keys should be
    /// refreshed, otherwise it indicates an invalid token.
    TokenMismatch,
    InvalidToken(jwt::errors::Error),
    /// # Optional
    ///
    /// This requires the optional `async` or `blocking` feature to be enabled.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "async", feature = "blocking"))))]
    #[cfg(any(feature = "async", feature = "blocking"))]
    ConnectionError(reqwest::Error),
    Other(String),
    ParseError(String),
}

impl Error for AuthErr {}

impl fmt::Display for AuthErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AuthErr::*;

        match self {
            InvalidState => write!(f, "No public keys found"),
            InvalidTokenState => write!(f, "No `kid` in token"),
            TokenMismatch => write!(f, "No public keys matched `kid` from token"),
            InvalidToken(err) => write!(f, "Invalid token. {err}"),
            #[cfg(any(feature = "async", feature = "blocking"))]
            ConnectionError(err) => write!(f, "Could not connect to Microsoft. {err}"),
            Other(msg) => write!(f, "An error occurred: {msg}"),
            ParseError(msg) => write!(f, "Could not parse token. {msg}"),
        }
    }
}

#[cfg(any(feature = "async", feature = "blocking"))]
impl From<reqwest::Error> for AuthErr {
    fn from(e: reqwest::Error) -> AuthErr {
        AuthErr::ConnectionError(e)
    }
}

impl From<jwt::errors::Error> for AuthErr {
    fn from(e: jwt::errors::Error) -> AuthErr {
        AuthErr::InvalidToken(e)
    }
}
