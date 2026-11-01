// SPDX-License-Identifier: MPL-2.0
// Ported from Polaris 56d52fb44958 internal/transport/xhttp; Xray b17a88f9b46d.
use super::{Error, config::Config};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue, Request};
impl Config {
    pub fn request(
        &self,
        authority: &str,
        secure: bool,
        session: &str,
        sequence: Option<u64>,
        upload: bool,
        payload: Option<&[u8]>,
    ) -> Result<Request<()>, Error> {
        let mut url = url::Url::parse(&format!(
            "{}://{authority}{}",
            if secure { "https" } else { "http" },
            self.path()
        ))
        .map_err(|_| bad())?;
        if let Some((_, q)) = self.path.split_once('?') {
            url.set_query(Some(q));
        }
        let mut headers = HeaderMap::new();
        for (k, v) in &self.headers {
            put(&mut headers, k, v)?;
        }
        if !headers.contains_key("user-agent") {
            put(
                &mut headers,
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
            )?;
            put(&mut headers, "Accept-Language", "en-US,en;q=0.9")?;
            put(&mut headers, "DNT", "1")?;
        } else if headers.get("user-agent").is_some_and(|v| v == "golang") {
            headers.remove("user-agent");
        }
        for (k, v) in [
            ("Sec-Fetch-Mode", "cors"),
            ("Sec-Fetch-Dest", "empty"),
            ("Sec-Fetch-Site", "same-origin"),
            ("Priority", "u=1, i"),
            ("Cache-Control", "no-cache"),
            ("Pragma", "no-cache"),
            ("Accept", "*/*"),
        ] {
            if !headers.contains_key(k) {
                put(&mut headers, k, v)?;
            }
        }
        let value = self.padding();
        let (place, key, header) = if self.xpadding_obfs_mode {
            (
                self.xpadding_placement.as_str(),
                self.xpadding_key.as_str(),
                self.xpadding_header.as_str(),
            )
        } else {
            ("queryInHeader", "x_padding", "Referer")
        };
        match place {
            "queryInHeader" => {
                let mut u = url.clone();
                u.set_query(None);
                u.query_pairs_mut().append_pair(key, &value);
                put(&mut headers, header, u.as_str())?;
            }
            "header" => put(&mut headers, header, &value)?,
            "query" => {
                url.query_pairs_mut().append_pair(key, &value);
            }
            "cookie" => cookie(&mut headers, key, &value)?,
            _ => return Err(bad()),
        }
        meta(
            &mut url,
            &mut headers,
            &self.session_id_placement,
            &self.session_id_key,
            session,
        )?;
        if let Some(seq) = sequence {
            meta(
                &mut url,
                &mut headers,
                &self.seq_placement,
                &self.seq_key,
                &seq.to_string(),
            )?;
        }
        if upload && sequence.is_none() && !self.no_grpc_header {
            put(&mut headers, "Content-Type", "application/grpc")?;
        }
        if let Some(payload) = payload
            && matches!(self.uplink_data_placement.as_str(), "header" | "cookie")
        {
            let encoded = URL_SAFE_NO_PAD.encode(payload);
            let mut offset = 0;
            let mut index = 0;
            while offset < encoded.len() {
                let n = self.uplink_chunk_size.random().min(encoded.len() - offset);
                let value = &encoded[offset..offset + n];
                if self.uplink_data_placement == "header" {
                    put(
                        &mut headers,
                        &format!("{}-{index}", self.uplink_data_key),
                        value,
                    )?;
                } else {
                    cookie(
                        &mut headers,
                        &format!("{}_{index}", self.uplink_data_key),
                        value,
                    )?;
                }
                offset += n;
                index += 1;
            }
        }
        let mut req = Request::builder()
            .method(if upload {
                self.uplink_http_method.as_str()
            } else {
                "GET"
            })
            .uri(url.as_str())
            .body(())
            .map_err(|_| bad())?;
        put(&mut headers, "Host", authority)?;
        *req.headers_mut() = headers;
        Ok(req)
    }
    pub fn matches(&self, request: &Request<()>) -> bool {
        let host = request
            .uri()
            .host()
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|h| h.split(':').next())
            })
            .unwrap_or_default();
        request.uri().path().starts_with(&self.path())
            && (self.host.is_empty() || self.host.eq_ignore_ascii_case(host))
    }
    pub fn extract(&self, req: &Request<()>) -> (String, String) {
        let path = self.path();
        let mut parts = req
            .uri()
            .path()
            .strip_prefix(&path)
            .unwrap_or_default()
            .split('/');
        let mut get = |p: &str, k: &str| -> String {
            match p {
                "path" => parts.next().unwrap_or_default().into(),
                "header" => header(req.headers(), k).into(),
                "cookie" => get_cookie(req.headers(), k),
                "query" => query(req.uri().query().unwrap_or_default(), k),
                _ => String::new(),
            }
        };
        (
            get(&self.session_id_placement, &self.session_id_key),
            get(&self.seq_placement, &self.seq_key),
        )
    }
    pub fn valid_padding(&self, req: &Request<()>) -> bool {
        let v = if !self.xpadding_obfs_mode {
            let r = header(req.headers(), "referer");
            if r.is_empty() {
                query(req.uri().query().unwrap_or_default(), "x_padding")
            } else {
                url_query(r, "x_padding")
            }
        } else {
            let c = get_cookie(req.headers(), &self.xpadding_key);
            let h = header(req.headers(), &self.xpadding_header);
            if !c.is_empty() {
                c
            } else if !h.is_empty() {
                if self.xpadding_placement == "header" {
                    h.into()
                } else {
                    url_query(h, &self.xpadding_key)
                }
            } else {
                query(req.uri().query().unwrap_or_default(), &self.xpadding_key)
            }
        };
        if v.is_empty() {
            return false;
        }
        let (n, t) = if self.xpadding_method == "tokenish" {
            (huffman_len(&v), 2)
        } else {
            (v.len(), 0)
        };
        n >= self.xpadding_bytes.from.saturating_sub(t) && n <= self.xpadding_bytes.to + t
    }
    pub fn response_headers(&self, req: &Request<()>) -> Result<HeaderMap, Error> {
        let mut h = HeaderMap::new();
        let origin = header(req.headers(), "origin");
        put(
            &mut h,
            "Access-Control-Allow-Origin",
            if origin.is_empty() { "*" } else { origin },
        )?;
        if [
            &self.session_id_placement,
            &self.seq_placement,
            &self.xpadding_placement,
            &self.uplink_data_placement,
        ]
        .contains(&&"cookie".to_owned())
        {
            put(&mut h, "Access-Control-Allow-Credentials", "true")?;
        }
        if req.method() == http::Method::OPTIONS {
            for (a, b) in [
                (
                    "Access-Control-Allow-Methods",
                    "access-control-request-method",
                ),
                (
                    "Access-Control-Allow-Headers",
                    "access-control-request-headers",
                ),
            ] {
                let v = header(req.headers(), b);
                put(&mut h, a, if v.is_empty() { "*" } else { v })?;
            }
        }
        let value = self.padding();
        if self.xpadding_obfs_mode {
            match self.xpadding_placement.as_str() {
                "header" => put(&mut h, &self.xpadding_header, &value)?,
                "queryInHeader" => put(
                    &mut h,
                    &self.xpadding_header,
                    &format!("?{}={value}", self.xpadding_key),
                )?,
                "cookie" => put(
                    &mut h,
                    "Set-Cookie",
                    &format!("{}={value}; Path=/", self.xpadding_key),
                )?,
                _ => {}
            }
        } else {
            put(&mut h, "X-Padding", &value)?;
        }
        Ok(h)
    }
    pub fn encoded_payload(&self, h: &HeaderMap) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        for place in ["header", "cookie"] {
            if self.uplink_data_placement != "auto" && self.uplink_data_placement != place {
                continue;
            }
            let mut text = String::new();
            for i in 0..=h.len().max(1) * 128 {
                let key = format!(
                    "{}{}{i}",
                    self.uplink_data_key,
                    if place == "header" { "-" } else { "_" }
                );
                let v = if place == "header" {
                    header(h, &key).to_owned()
                } else {
                    get_cookie(h, &key)
                };
                if v.is_empty() {
                    break;
                }
                if text.len() + v.len() > self.server_max_header_bytes {
                    return Err(bad());
                }
                text.push_str(&v);
            }
            let decoded = URL_SAFE_NO_PAD.decode(text).map_err(|_| bad())?;
            if data.len() + decoded.len() > self.sc_max_each_post_bytes.to {
                return Err(bad());
            }
            data.extend(decoded);
        }
        Ok(data)
    }
    fn padding(&self) -> String {
        let n = self.xpadding_bytes.random();
        if self.xpadding_method != "tokenish" {
            return "X".repeat(n);
        }
        const TABLE: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut b = vec![0; n * 5 / 4 + 1];
        if getrandom::fill(&mut b).is_err() {
            return "X".repeat(n);
        }
        for c in &mut b {
            *c = TABLE[*c as usize % TABLE.len()];
        }
        let mut v = String::from_utf8(b).expect("ASCII alphabet");
        loop {
            let len = huffman_len(&v);
            if len.abs_diff(n) <= 2 {
                return v;
            }
            if len > n {
                v.pop();
            } else {
                v.push('X');
            }
        }
    }
}
fn header<'a>(h: &'a HeaderMap, k: &str) -> &'a str {
    h.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default()
}
fn query(q: &str, k: &str) -> String {
    url::form_urlencoded::parse(q.as_bytes())
        .find_map(|(key, v)| (key == k).then(|| v.into_owned()))
        .unwrap_or_default()
}
fn url_query(u: &str, k: &str) -> String {
    u.split_once('?')
        .map(|(_, q)| query(q, k))
        .unwrap_or_default()
}
fn get_cookie(h: &HeaderMap, k: &str) -> String {
    h.get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .find_map(|(key, v)| (key == k).then(|| v.to_owned()))
        .unwrap_or_default()
}
fn put(h: &mut HeaderMap, k: &str, v: &str) -> Result<(), Error> {
    h.insert(
        http::HeaderName::from_bytes(k.as_bytes()).map_err(|_| bad())?,
        HeaderValue::from_str(v).map_err(|_| bad())?,
    );
    Ok(())
}
fn cookie(h: &mut HeaderMap, k: &str, v: &str) -> Result<(), Error> {
    let old = header(h, "cookie");
    let value = if old.is_empty() {
        format!("{k}={v}")
    } else {
        format!("{old}; {k}={v}")
    };
    put(h, "Cookie", &value)
}
fn meta(u: &mut url::Url, h: &mut HeaderMap, p: &str, k: &str, v: &str) -> Result<(), Error> {
    if v.is_empty() {
        return Ok(());
    }
    match p {
        "path" => {
            let path = format!(
                "{}{v}",
                if u.path().ends_with('/') {
                    u.path().to_owned()
                } else {
                    format!("{}/", u.path())
                }
            );
            u.set_path(&path);
        }
        "query" => {
            u.query_pairs_mut().append_pair(k, v);
        }
        "header" => put(h, k, v)?,
        "cookie" => cookie(h, k, v)?,
        _ => return Err(bad()),
    }
    Ok(())
}
fn bad() -> Error {
    Error::Configuration("XHTTP request")
}
fn huffman_len(s: &str) -> usize {
    s.bytes()
        .map(|b| HPACK_BITS[b as usize] as usize)
        .sum::<usize>()
        .div_ceil(8)
}

// RFC 7541 Appendix B: number of bits in each octet code.
// Table from golang.org/x/net/http2/hpack (Go Authors), BSD-3-Clause.
// See LICENSES/Go-BSD-3-Clause.txt and THIRD_PARTY.md.
const HPACK_BITS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn metadata_payload_and_padding_roundtrip_all_placements() {
        for pad in ["queryInHeader", "query", "header", "cookie"] {
            for method in ["repeat-x", "tokenish"] {
                for session in ["path", "query", "header", "cookie"] {
                    for seq in ["path", "query", "header", "cookie"] {
                        for payload in ["body", "header", "cookie"] {
                            let extra = json!({"xPaddingObfsMode":true,"xPaddingPlacement":pad,"xPaddingMethod":method,"xPaddingBytes":"100-110","sessionIDPlacement":session,"seqPlacement":seq,"uplinkDataPlacement":payload,"uplinkChunkSize":64});
                            let c = Config::parse(
                                "localhost",
                                "/relay?token=a%2Fb",
                                "packet-up",
                                &extra.to_string(),
                            )
                            .unwrap();
                            let data = (0..256).map(|i| i as u8).collect::<Vec<_>>();
                            let r = c
                                .request("localhost", true, "abc123", Some(17), true, Some(&data))
                                .unwrap();
                            assert!(c.matches(&r));
                            assert!(c.valid_padding(&r), "{pad}/{method}");
                            assert_eq!(c.extract(&r), ("abc123".into(), "17".into()));
                            assert!(r.uri().query().unwrap().contains("token=a%2Fb"));
                            if payload != "body" {
                                assert_eq!(c.encoded_payload(r.headers()).unwrap(), data);
                            }
                        }
                    }
                }
            }
        }
        let c = Config::parse("localhost", "/relay", "auto", "").unwrap();
        let mut r = c
            .request("localhost", false, "id", None, false, None)
            .unwrap();
        assert!(c.valid_padding(&r));
        r.headers_mut().remove("referer");
        assert!(!c.valid_padding(&r));
    }
}
