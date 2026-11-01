// SPDX-License-Identifier: MPL-2.0
// Ported from perfect-panel/Polaris internal/transport/xhttp at 56d52fb44958.
// Derived from XTLS/Xray-core splithttp at b17a88f9b46d.
use super::Error;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Range {
    pub from: usize,
    pub to: usize,
}
impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        let parse = || -> Option<Self> {
            let (a, b) = match v {
                serde_json::Value::Number(n) => {
                    let n = usize::try_from(n.as_u64()?).ok()?;
                    (n, n)
                }
                serde_json::Value::String(s) => {
                    if s.is_empty() {
                        (0, 0)
                    } else if let Ok(n) = s.parse() {
                        (n, n)
                    } else {
                        let (a, b) = s.split_once('-')?;
                        (a.parse().ok()?, b.parse().ok()?)
                    }
                }
                serde_json::Value::Object(o) => (
                    usize::try_from(match o.get("from") {
                        None => 0,
                        Some(v) => v.as_u64()?,
                    })
                    .ok()?,
                    usize::try_from(match o.get("to") {
                        None => 0,
                        Some(v) => v.as_u64()?,
                    })
                    .ok()?,
                ),
                _ => return None,
            };
            if a > i32::MAX as usize || b > i32::MAX as usize {
                return None;
            }
            Some(Self {
                from: a.min(b),
                to: a.max(b),
            })
        };
        parse().ok_or_else(|| serde::de::Error::custom("invalid nonnegative XHTTP range"))
    }
}
impl Range {
    pub fn fixed(n: usize) -> Self {
        Self { from: n, to: n }
    }
    pub fn random(self) -> usize {
        if self.from == self.to {
            return self.from;
        }
        let mut b = [0; 8];
        if getrandom::fill(&mut b).is_err() {
            return self.from;
        }
        self.from + (u64::from_le_bytes(b) % (self.to - self.from + 1) as u64) as usize
    }
    fn default_to(&mut self, from: usize, to: usize) {
        if self.to == 0 {
            *self = Self { from, to };
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Xmux {
    pub max_concurrency: Range,
    pub max_connections: Range,
    pub c_max_reuse_times: Range,
    pub h_max_request_times: Range,
    pub h_max_reusable_secs: Range,
    pub h_keep_alive_period: usize,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "host")]
    pub host: String,
    #[serde(rename = "path")]
    pub path: String,
    #[serde(rename = "mode")]
    pub mode: String,
    #[serde(rename = "serverBackend")]
    pub server_backend: String,
    #[serde(rename = "headers")]
    pub headers: BTreeMap<String, String>,
    #[serde(rename = "xPaddingBytes")]
    pub xpadding_bytes: Range,
    #[serde(rename = "xPaddingObfsMode")]
    pub xpadding_obfs_mode: bool,
    #[serde(rename = "xPaddingKey")]
    pub xpadding_key: String,
    #[serde(rename = "xPaddingHeader")]
    pub xpadding_header: String,
    #[serde(rename = "xPaddingPlacement")]
    pub xpadding_placement: String,
    #[serde(rename = "xPaddingMethod")]
    pub xpadding_method: String,
    #[serde(rename = "uplinkHTTPMethod")]
    pub uplink_http_method: String,
    #[serde(rename = "sessionIDPlacement")]
    pub session_id_placement: String,
    #[serde(rename = "sessionIDKey")]
    pub session_id_key: String,
    #[serde(rename = "sessionIDTable")]
    pub session_id_table: String,
    #[serde(rename = "sessionIDLength")]
    pub session_id_length: Range,
    #[serde(rename = "seqPlacement")]
    pub seq_placement: String,
    #[serde(rename = "seqKey")]
    pub seq_key: String,
    #[serde(rename = "uplinkDataPlacement")]
    pub uplink_data_placement: String,
    #[serde(rename = "uplinkDataKey")]
    pub uplink_data_key: String,
    #[serde(rename = "uplinkChunkSize")]
    pub uplink_chunk_size: Range,
    #[serde(rename = "noGRPCHeader")]
    pub no_grpc_header: bool,
    #[serde(rename = "noSSEHeader")]
    pub no_sse_header: bool,
    #[serde(rename = "scMaxEachPostBytes")]
    pub sc_max_each_post_bytes: Range,
    #[serde(rename = "scMinPostsIntervalMs")]
    pub sc_min_posts_interval_ms: Range,
    #[serde(rename = "scMaxBufferedPosts")]
    pub sc_max_buffered_posts: usize,
    #[serde(rename = "scMaxBufferedBytes")]
    pub sc_max_buffered_bytes: usize,
    #[serde(rename = "scMaxTotalBufferedBytes")]
    pub sc_max_total_buffered_bytes: usize,
    #[serde(rename = "scMaxActiveSessions")]
    pub sc_max_active_sessions: usize,
    #[serde(rename = "scMaxConcurrentRequests")]
    pub sc_max_concurrent_requests: usize,
    #[serde(rename = "scStreamUpServerSecs")]
    pub sc_stream_up_server_secs: Range,
    #[serde(rename = "serverMaxHeaderBytes")]
    pub server_max_header_bytes: usize,
    #[serde(rename = "h3InitialStreamReceiveWindow")]
    pub h3_initial_stream_receive_window: usize,
    #[serde(rename = "h3MaxStreamReceiveWindow")]
    pub h3_max_stream_receive_window: usize,
    #[serde(rename = "h3InitialConnectionReceiveWindow")]
    pub h3_initial_connection_receive_window: usize,
    #[serde(rename = "h3MaxConnectionReceiveWindow")]
    pub h3_max_connection_receive_window: usize,
    #[serde(rename = "xmux")]
    pub xmux: Xmux,
    #[serde(rename = "downloadSettings", skip_serializing_if = "Option::is_none")]
    pub download: Option<Download>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<serde_json::Value>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Download {
    pub address: String,
    pub port: u16,
    pub method: String,
    pub network: String,
    pub security: String,
    pub tls_settings: Tls,
    #[serde(rename = "xhttpSettings")]
    pub xhttp: Option<Box<Config>>,
    #[serde(rename = "splithttpSettings")]
    pub splithttp: Option<Box<Config>>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Tls {
    pub server_name: String,
    pub allow_insecure: bool,
    pub alpn: Vec<String>,
}
impl Config {
    pub fn parse(host: &str, path: &str, mode: &str, extra: &str) -> Result<Self, Error> {
        if extra.len() > 65536 {
            return Err(invalid());
        }
        let mut c = if extra.trim().is_empty() {
            Self::default()
        } else {
            serde_json::from_str(extra).map_err(|_| invalid())?
        };
        c.host = host.into();
        c.path = path.into();
        c.mode = mode.into();
        c.normalize(0)?;
        Ok(c)
    }
    fn normalize(&mut self, depth: usize) -> Result<(), Error> {
        if depth > 1 {
            return Err(invalid());
        }
        if let Some(v) = self.extra.take() {
            let mut c: Self = serde_json::from_value(v).map_err(|_| invalid())?;
            c.host = self.host.clone();
            c.path = self.path.clone();
            c.mode = self.mode.clone();
            if c.extra.is_some() {
                return Err(invalid());
            }
            *self = c;
        }
        default(&mut self.mode, "auto");
        allowed(
            &self.mode,
            &["auto", "packet-up", "stream-up", "stream-one"],
        )?;
        allowed(&self.server_backend, &["", "net/http"])?;
        if self.host.len() > 255
            || (!self.host.is_empty() && self.host.parse::<http::uri::Authority>().is_err())
            || self.path.len() > 4096
            || self.path.contains(['\r', '\n', '#'])
        {
            return Err(invalid());
        }
        if self.headers.len() > 64 {
            return Err(invalid());
        }
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case("host")
                || http::HeaderName::from_bytes(k.as_bytes()).is_err()
                || http::HeaderValue::from_str(v).is_err()
                || v.len() > 8192
            {
                return Err(invalid());
            }
        }
        self.xpadding_bytes.default_to(100, 1000);
        if self.xpadding_bytes.from == 0 || self.xpadding_bytes.to > 16384 {
            return Err(invalid());
        }
        default(&mut self.xpadding_key, "x_padding");
        default(&mut self.xpadding_header, "X-Padding");
        default(&mut self.xpadding_placement, "queryInHeader");
        default(&mut self.xpadding_method, "repeat-x");
        allowed(
            &self.xpadding_placement,
            &["queryInHeader", "header", "query", "cookie"],
        )?;
        allowed(&self.xpadding_method, &["repeat-x", "tokenish"])?;
        default(&mut self.uplink_data_placement, "auto");
        allowed(
            &self.uplink_data_placement,
            &["auto", "body", "header", "cookie"],
        )?;
        default(&mut self.uplink_http_method, "POST");
        self.uplink_http_method.make_ascii_uppercase();
        if self.uplink_http_method.parse::<http::Method>().is_err()
            || self.uplink_http_method.len() > 32
        {
            return Err(invalid());
        }
        if (self.uplink_http_method == "GET"
            || matches!(self.uplink_data_placement.as_str(), "header" | "cookie"))
            && self.mode != "packet-up"
        {
            return Err(invalid());
        }
        default(&mut self.session_id_placement, "path");
        default(&mut self.seq_placement, "path");
        for p in [&self.session_id_placement, &self.seq_placement] {
            allowed(p, &["path", "header", "query", "cookie"])?;
        }
        default(
            &mut self.session_id_key,
            if self.session_id_placement == "header" {
                "X-Session"
            } else {
                "x_session"
            },
        );
        default(
            &mut self.seq_key,
            if self.seq_placement == "header" {
                "X-Seq"
            } else {
                "x_seq"
            },
        );
        default(
            &mut self.uplink_data_key,
            if self.uplink_data_placement == "cookie" {
                "x_data"
            } else {
                "X-Data"
            },
        );
        for key in [
            &self.xpadding_key,
            &self.xpadding_header,
            &self.session_id_key,
            &self.seq_key,
            &self.uplink_data_key,
        ] {
            if key.len() > 128
                || key.is_empty()
                || http::HeaderName::from_bytes(key.as_bytes()).is_err()
            {
                return Err(invalid());
            }
        }
        self.session_table()?;
        self.sc_max_each_post_bytes.default_to(1_000_000, 1_000_000);
        if self.sc_max_each_post_bytes.from == 0 || self.sc_max_each_post_bytes.to > 16 << 20 {
            return Err(invalid());
        }
        self.sc_min_posts_interval_ms.default_to(30, 30);
        self.sc_stream_up_server_secs.default_to(20, 80);
        limit(&mut self.sc_max_buffered_posts, 30, 65536)?;
        limit(&mut self.sc_max_buffered_bytes, 4 << 20, 1 << 30)?;
        self.sc_max_buffered_bytes = self
            .sc_max_buffered_bytes
            .max(self.sc_max_each_post_bytes.to);
        limit(&mut self.sc_max_total_buffered_bytes, 256 << 20, 1 << 34)?;
        self.sc_max_total_buffered_bytes = self
            .sc_max_total_buffered_bytes
            .max(self.sc_max_buffered_bytes);
        limit(&mut self.sc_max_active_sessions, 16384, 1 << 20)?;
        limit(&mut self.sc_max_concurrent_requests, 16384, 1 << 20)?;
        limit(&mut self.server_max_header_bytes, 8192, 1 << 20)?;
        if self.server_max_header_bytes < 1024 {
            return Err(invalid());
        }
        if self.uplink_chunk_size.to == 0 {
            self.uplink_chunk_size = match self.uplink_data_placement.as_str() {
                "header" => Range {
                    from: 3000,
                    to: 4000,
                },
                "cookie" => Range {
                    from: 2048,
                    to: 3072,
                },
                _ => self.sc_max_each_post_bytes,
            };
        } else {
            self.uplink_chunk_size.from = self.uplink_chunk_size.from.max(64);
            self.uplink_chunk_size.to = self.uplink_chunk_size.to.max(64);
        }
        limit(
            &mut self.h3_initial_stream_receive_window,
            512 << 10,
            1 << 30,
        )?;
        limit(&mut self.h3_max_stream_receive_window, 4 << 20, 1 << 30)?;
        limit(
            &mut self.h3_initial_connection_receive_window,
            1 << 20,
            1 << 30,
        )?;
        limit(
            &mut self.h3_max_connection_receive_window,
            16 << 20,
            1 << 30,
        )?;
        if self.h3_initial_stream_receive_window > self.h3_max_stream_receive_window
            || self.h3_initial_connection_receive_window > self.h3_max_connection_receive_window
            || self.h3_initial_connection_receive_window < self.h3_initial_stream_receive_window
            || self.h3_max_connection_receive_window < self.h3_max_stream_receive_window
        {
            return Err(invalid());
        }
        if self.xmux.max_concurrency.to > 0 && self.xmux.max_connections.to > 0 {
            return Err(invalid());
        }
        if self.xmux == Xmux::default() {
            self.xmux.max_connections = Range::fixed(3);
            self.xmux.h_max_request_times = Range { from: 600, to: 900 };
            self.xmux.h_max_reusable_secs = Range {
                from: 1800,
                to: 3000,
            };
        }
        if self.xmux.max_connections.to > 128
            || self.xmux.max_concurrency.to > 1024
            || self.xmux.h_keep_alive_period > 86400
        {
            return Err(invalid());
        }
        if let Some(d) = &mut self.download {
            if self.mode == "stream-one"
                || depth > 0
                || d.address.len() > 255
                || d.address.is_empty()
                || d.port == 0
            {
                return Err(invalid());
            }
            let network = if d.method.is_empty() {
                &d.network
            } else {
                &d.method
            };
            allowed(&network.to_ascii_lowercase(), &["xhttp", "splithttp"])?;
            allowed(&d.security, &["", "none", "tls"])?;
            let c = d
                .xhttp
                .as_mut()
                .or(d.splithttp.as_mut())
                .ok_or_else(invalid)?;
            c.normalize(depth + 1)?;
        }
        Ok(())
    }
    fn session_table(&mut self) -> Result<(), Error> {
        let table = match self.session_id_table.as_str() {
            "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "HEX" => "0123456789ABCDEF",
            "alphabet" => "abcdefghijklmnopqrstuvwxyz",
            "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
            "hex" => "0123456789abcdef",
            "number" => "0123456789",
            s => s,
        };
        if !table.is_empty() {
            if self.session_id_length.from == 0
                || self.session_id_length.to > 4096
                || !table
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
            {
                return Err(invalid());
            }
            let mut room = 0u64;
            for n in self.session_id_length.from..=self.session_id_length.to {
                room = room.saturating_add((table.len() as u64).saturating_pow(n as u32));
                if room >= 2 << 30 {
                    break;
                }
            }
            if room < 2 << 30 {
                return Err(invalid());
            }
        }
        self.session_id_table = table.into();
        Ok(())
    }
    pub fn path(&self) -> String {
        let mut p = self.path.split('?').next().unwrap_or_default().to_owned();
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        if (self.session_id_placement == "path" || self.seq_placement == "path")
            && !p.ends_with('/')
        {
            p.push('/');
        }
        p
    }
    pub fn session_id(&self) -> Result<String, Error> {
        if !self.session_id_table.is_empty() {
            let mut b = vec![0; self.session_id_length.random()];
            getrandom::fill(&mut b).map_err(|_| invalid())?;
            let t = self.session_id_table.as_bytes();
            for v in &mut b {
                *v = t[*v as usize % t.len()];
            }
            return String::from_utf8(b).map_err(|_| invalid());
        }
        let mut b = [0; 16];
        getrandom::fill(&mut b).map_err(|_| invalid())?;
        b[6] = (b[6] & 15) | 64;
        b[8] = (b[8] & 63) | 128;
        Ok(uuid::Uuid::from_bytes(b).hyphenated().to_string())
    }
}
fn default(s: &mut String, v: &str) {
    if s.is_empty() {
        *s = v.into();
    }
}
fn limit(n: &mut usize, default: usize, max: usize) -> Result<(), Error> {
    if *n == 0 {
        *n = default;
    }
    if *n > max { Err(invalid()) } else { Ok(()) }
}
fn allowed(v: &str, values: &[&str]) -> Result<(), Error> {
    if values.contains(&v) {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn invalid() -> Error {
    Error::Configuration("XHTTP options")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_and_configuration_limits_reject_malformed_values() {
        for text in [
            "-1",
            "\"-1\"",
            "{\"from\":-1,\"to\":3}",
            "{\"from\":\"1\",\"to\":3}",
            "2147483648",
            "\"3-no\"",
        ] {
            assert!(serde_json::from_str::<Range>(text).is_err(), "{text}");
        }
        assert_eq!(
            serde_json::from_str::<Range>("\"9-3\"").unwrap(),
            Range { from: 3, to: 9 }
        );
        for extra in [
            r#"{"xmux":{"maxConnections":2,"maxConcurrency":3}}"#,
            r#"{"scMaxBufferedPosts":-1}"#,
            r#"{"scMaxEachPostBytes":16777217}"#,
            r#"{"headers":{"Host":"example.com"}}"#,
            r#"{"xPaddingBytes":"0-20"}"#,
            r#"{"sessionIDTable":"number","sessionIDLength":3}"#,
            r#"{"h3InitialStreamReceiveWindow":8000000,"h3MaxStreamReceiveWindow":1000000}"#,
        ] {
            assert!(
                Config::parse("localhost", "/relay", "auto", extra).is_err(),
                "{extra}"
            );
        }
        assert!(
            Config::parse(
                "localhost",
                "/relay",
                "stream-one",
                r#"{"uplinkDataPlacement":"cookie"}"#
            )
            .is_err()
        );
        let c=Config::parse("localhost","/relay?token=a%2Fb","packet-up",r#"{"xPaddingBytes":300,"extra":{"xPaddingBytes":101,"sessionIDTable":"hex","sessionIDLength":16}}"#).unwrap();
        assert_eq!(c.xpadding_bytes, Range::fixed(101));
        assert_eq!(c.host, "localhost");
        assert_eq!(c.path(), "/relay/");
        assert_eq!(c.session_id().unwrap().len(), 16);
    }
}
