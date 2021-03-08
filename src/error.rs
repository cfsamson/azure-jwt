use crate::jwt;
use std::{error::Error, fmt};

#[derive(Debug)]
pub enum AuthErr {
    InvalidToken(jwt::errors::Error),
    ConnectionError(reqwest::Error),
    Other(String),
    ParseError(String),
}

impl Error for AuthErr {}

impl fmt::Display for AuthErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use AuthErr::*;

        match self {
            InvalidToken(err) => write!(f, "Invalid token. {}", err),
            ConnectionError(err) => write!(f, "Could not connect to Microsoft. {}", err),
            Other(msg) => write!(f, "An error occurred: {}", msg),
            ParseError(msg) => write!(f, "Could not parse token. {}", msg),
        }
    }
}

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
