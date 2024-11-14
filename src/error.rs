//! Error definitions

/// Library result type
pub type Result<T> = std::result::Result<T, Error>;

/// Library errors
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum Error {
    // Basic errors
    #[error("Unknown error: {0}")]
    Unknown(String),
    #[error("IO error: {0}")]
    IO(String),
    // TODO: Parse should contain line number + line contents here
    #[error("Parse error: {err} (line {lc}: `{line}`)")]
    Parse {
        err: String,
        lc: usize,
        line: String,
    },
    // TODO: remove unused errors
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Not completed: {0}")]
    NotCompleted(String),
    #[error("Timeout reached")]
    Timeout,
    #[error("Max number of retries reached")]
    MaxRetries,
    #[error("Invalid Patp: {0}")]
    InvalidPatP(String),
    #[error("Invalid PatTas: {0}")]
    InvalidPatTas(String),
    #[error("Encryption: {0}")]
    Encryption(String),
    #[error("Misconfigured Job: {0}")]
    MisconfiguredJob(String),

    // Specific errors
    #[error("User is already in this fleet")]
    UserAlreadyInFleet,
    #[error("Cannot join a whitelabel fleet via redhorizon")]
    CantJoinWhitelabelFleet,
    #[error("Invalid lus code: {0}")]
    InvalidLusCode(String),

    #[error("Error querying satellite: {0}")]
    Satellite(String),
    #[error("Error during execution on ship: {0}")]
    ExecuteOnShip(String),

    // External crate error forwards
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Scheduler error: {0}")]
    Scheduler(String),
    #[error("Reqwest error: {0}")]
    Reqwest(String),
    #[error("S3 error: {0}")]
    S3(String),
    #[error("SMTP error: {0}")]
    Smtp(String),
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

    #[inline]
    pub fn log_warn(self) -> Self {
        log::warn!("{}", self);
        self
    }

    #[inline]
    pub fn log_error(self) -> Self {
        log::error!("{}", self);
        self
    }
}

//impl From<&str> for Error {
//    fn from(err: &str) -> Self {
//        Error::Unknown(err.to_owned())
//    }
//}
//
//impl From<std::convert::Infallible> for Error {
//    fn from(err: std::convert::Infallible) -> Self {
//        Error::IO(err.to_string())
//    }
//}
//
//impl From<std::io::Error> for Error {
//    fn from(err: std::io::Error) -> Self {
//        Error::IO(err.to_string())
//    }
//}

//impl From<std::str::Utf8Error> for Error {
//    fn from(value: std::str::Utf8Error) -> Self {
//        Error::Parse(format!("Unable to parse utf8: {}", value))
//    }
//}

//impl From<sqlx::error::Error> for Error {
//    fn from(value: sqlx::error::Error) -> Self {
//        Error::Database(value.to_string())
//    }
//}
//
//impl From<tokio_cron_scheduler::JobSchedulerError> for Error {
//    fn from(value: tokio_cron_scheduler::JobSchedulerError) -> Self {
//        Error::Scheduler(value.to_string())
//    }
//}
//
//impl From<uuid::Error> for Error {
//    fn from(value: uuid::Error) -> Self {
//        Error::Parse(value.to_string())
//    }
//}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::Reqwest(value.to_string())
    }
}

//impl From<serde_json::Error> for Error {
//    fn from(value: serde_json::Error) -> Self {
//        Error::Parse(value.to_string())
//    }
//}
//
//impl From<lettre::error::Error> for Error {
//    fn from(value: lettre::error::Error) -> Self {
//        Error::Smtp(value.to_string())
//    }
//}
