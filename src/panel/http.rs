// SPDX-License-Identifier: GPL-3.0-only

//! HTTP mechanics only: URL construction, bounds, deadlines and safe errors.

use std::time::Duration;

use reqwest::{
    Method,
    header::{ACCEPT, CONTENT_TYPE, ETAG, IF_NONE_MATCH},
};
use url::Url;

use super::{Encoding, Endpoint, Error, ErrorKind, Result, Secret};

pub(crate) struct Http {
    client: reqwest::Client,
    base: Url,
    secret: Secret,
    max_response_bytes: usize,
}

pub(crate) struct Request<'a> {
    pub endpoint: Endpoint,
    pub path: &'a str,
    pub method: Method,
    pub query: &'a [(&'a str, String)],
    pub encoding: Encoding,
    pub etag: Option<&'a str>,
    pub body: Option<Vec<u8>>,
    pub fingerprint: Option<&'a str>,
}

pub(crate) struct Response {
    pub status: u16,
    pub encoding: Option<Encoding>,
    pub etag: Option<String>,
    pub body: Vec<u8>,
}

pub(crate) fn validate_url(value: &str) -> Result<Url> {
    let mut base =
        Url::parse(value).map_err(|_| Error::input(Endpoint::Connection, "invalid panel URL"))?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(Error::input(
            Endpoint::Connection,
            "panel URL must be HTTP(S), without credentials, query or fragment",
        ));
    }
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    Ok(base)
}

impl Http {
    pub fn new(
        base: Url,
        secret: Secret,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .user_agent(concat!("Terraris/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| {
                Error::new(
                    Endpoint::Connection,
                    ErrorKind::Transport,
                    "HTTP client initialization failed",
                )
            })?;
        Ok(Self {
            client,
            base,
            secret,
            max_response_bytes,
        })
    }

    pub async fn send(&self, request: Request<'_>) -> Result<Response> {
        let endpoint = request.endpoint;
        // Every path is adapter-owned and relative to the configured API prefix.
        let mut url = self
            .base
            .join(request.path.trim_start_matches('/'))
            .map_err(|_| Error::input(endpoint, "invalid endpoint path"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("secret_key", self.secret.expose());
            for (key, value) in request.query {
                query.append_pair(key, value);
            }
        }
        let content_type = match request.encoding {
            Encoding::Json => "application/json",
            Encoding::Protobuf => "application/protobuf",
        };
        let mut builder = self
            .client
            .request(request.method, url)
            .header(ACCEPT, content_type);
        if let Some(etag) = request.etag {
            builder = builder.header(IF_NONE_MATCH, etag);
        }
        if let Some(body) = request.body {
            builder = builder.header(CONTENT_TYPE, content_type).body(body);
        }
        if let Some(fingerprint) = request.fingerprint {
            builder = builder.header("X-Node-Certificate-SHA256", fingerprint);
        }
        let mut response = builder
            .send()
            .await
            .map_err(|e| transport_error(endpoint, &e))?;
        let status = response.status().as_u16();
        // Discard error bodies: they may echo the URL, credentials or request.
        if status != 200 && status != 304 {
            return Ok(Response {
                status,
                encoding: None,
                etag: None,
                body: Vec::new(),
            });
        }
        let encoding = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .and_then(
                |s| match s.split(';').next()?.trim().to_ascii_lowercase().as_str() {
                    "application/json" => Some(Encoding::Json),
                    "application/protobuf" => Some(Encoding::Protobuf),
                    _ => None,
                },
            );
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|h| h.to_str().ok())
            .filter(|s| !s.is_empty() && s.len() <= 1024)
            .map(str::to_owned);
        if status == 304 {
            return Ok(Response {
                status,
                encoding,
                etag,
                body: Vec::new(),
            });
        }
        if response
            .content_length()
            .is_some_and(|n| n > self.max_response_bytes as u64)
        {
            return Err(Error::new(
                endpoint,
                ErrorKind::ResponseTooLarge,
                "response exceeds configured limit",
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| transport_error(endpoint, &e))?
        {
            if chunk.len() > self.max_response_bytes.saturating_sub(body.len()) {
                return Err(Error::new(
                    endpoint,
                    ErrorKind::ResponseTooLarge,
                    "response exceeds configured limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            encoding,
            etag,
            body,
        })
    }
}

fn transport_error(endpoint: Endpoint, error: &reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::new(endpoint, ErrorKind::Timeout, "panel request timed out")
    } else {
        Error::new(endpoint, ErrorKind::Transport, "panel transport failed")
    }
}
