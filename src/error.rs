//! Error definitions

/// Library result type
pub type Result<T> = std::result::Result<T, Error>;

/// Library errors
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum Error {
    #[error("IO error: {0}")]
    IO(String),
    #[error("Element not found: {0}")]
    NotFound(String),
    #[error("Parse error: {err} (line {lc}: `{line}`)")]
    Parse {
        err: String,
        lc: usize,
        line: String,
    },
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Max number of retries reached")]
    MaxRetries,
    #[error("Reqwest error: {0}")]
    Reqwest(String),
}

impl Error {
    #[inline]
    pub fn parse(err: &str, line_index: usize, line: &str) -> Self {
        Self::Parse {
            err: err.to_string(),
            lc: line_index + 1,
            line: line.to_string(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IO(err.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::Reqwest(value.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::Deserialization(value.to_string())
    }
}
