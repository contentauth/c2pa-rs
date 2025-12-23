use std::io;

// CBOR error type
#[derive(Debug)]
pub enum Error {
    /// IO error
    Io(io::Error),
    /// Invalid UTF-8 in string
    InvalidUtf8,
    /// Unexpected end of input
    Eof,
    /// Invalid CBOR value or syntax
    Syntax(String),
    /// Trailing data after value
    TrailingData,
    /// General message (serde compatibility)
    Message(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::InvalidUtf8 => write!(f, "Invalid UTF-8"),
            Error::Eof => write!(f, "Unexpected end of input"),
            Error::Syntax(s) => write!(f, "Syntax error: {}", s),
            Error::TrailingData => write!(f, "Trailing data"),
            Error::Message(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
