// SPDX-License-Identifier: GPL-3.0-only

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Connection,
    Config,
    Users,
    Alive,
    Device,
    Online,
    Traffic,
    Status,
}

impl Endpoint {
    pub fn path(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Config => "/v2/server/{server_id}",
            Self::Users => "/v1/server/user",
            Self::Alive => "/v1/server/alivelist",
            Self::Device => "/v1/server/device",
            Self::Online => "/v1/server/online",
            Self::Traffic => "/v1/server/push",
            Self::Status => "/v1/server/status",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidInput,
    Transport,
    Timeout,
    Http,
    Business,
    Decode,
    Schema,
    ResponseTooLarge,
    UnsupportedContentType,
    ValidatorScope,
    UnexpectedNotModified,
}

/// Only trusted static descriptions and numeric codes are retained. In
/// particular, reqwest URLs, parser errors and panel messages are not sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub endpoint: Endpoint,
    pub kind: ErrorKind,
    pub http_status: Option<u16>,
    pub business_code: Option<u32>,
    detail: &'static str,
}

impl Error {
    pub(crate) fn new(endpoint: Endpoint, kind: ErrorKind, detail: &'static str) -> Self {
        Self {
            endpoint,
            kind,
            detail,
            http_status: None,
            business_code: None,
        }
    }

    pub(crate) fn http(endpoint: Endpoint, status: u16) -> Self {
        Self {
            http_status: Some(status),
            ..Self::new(endpoint, ErrorKind::Http, "HTTP request rejected")
        }
    }

    pub(crate) fn business(endpoint: Endpoint, code: u32) -> Self {
        Self {
            business_code: Some(code),
            ..Self::new(endpoint, ErrorKind::Business, "panel rejected request")
        }
    }

    pub(crate) fn input(endpoint: Endpoint, detail: &'static str) -> Self {
        Self::new(endpoint, ErrorKind::InvalidInput, detail)
    }

    pub(crate) fn schema(endpoint: Endpoint, detail: &'static str) -> Self {
        Self::new(endpoint, ErrorKind::Schema, detail)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.endpoint.path(), self.detail)?;
        if let Some(status) = self.http_status {
            write!(f, " (HTTP {status})")?;
        }
        if let Some(code) = self.business_code {
            write!(f, " (code {code})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}
