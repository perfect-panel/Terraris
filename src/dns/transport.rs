// SPDX-License-Identifier: GPL-3.0-only
use super::{Error, Settings, system::System, wire};
use crate::{
    buffer::{BufferLayout, BufferScope},
    panel::DnsResolver,
    route::{self, Selectors, geodata::Catalog},
    task::CancellationToken,
    time::{Deadline, OperationContext},
};
use rustls::pki_types::ServerName;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Udp,
    Tcp,
    Tls,
    Https,
}
pub(crate) struct Server {
    pub(crate) selector: Selectors,
    pub(crate) default: bool,
    kind: Kind,
    host: String,
    port: u16,
    server_name: String,
    url: Option<url::Url>,
    http_host: String,
    client: Option<reqwest::Client>,
    tls: Arc<rustls::ClientConfig>,
    system: Arc<System>,
    settings: Settings,
}
struct Bootstrap {
    host: String,
    system: Arc<System>,
    settings: Settings,
}
impl reqwest::dns::Resolve for Bootstrap {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = self.host.clone();
        let system = self.system.clone();
        let settings = self.settings.clone();
        Box::pin(async move {
            let context = OperationContext::new(
                CancellationToken::new(),
                Some(
                    Deadline::after(Duration::from_secs(settings.timeout_seconds))
                        .map_err(|_| std::io::Error::other("bootstrap timeout"))?,
                ),
            );
            let ips = bootstrap(&host, &system, &settings, &context)
                .await
                .map_err(|_| std::io::Error::other("DNS bootstrap failed"))?;
            let addresses: reqwest::dns::Addrs =
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addresses)
        })
    }
}
pub(crate) fn tls_config(
    settings: &Settings,
    catalog: &mut Catalog,
) -> Result<Arc<rustls::ClientConfig>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &settings.ca_file {
        let (bytes, stamp) = crate::route::geodata::read(path, 1 << 20)
            .map_err(|_| Error::Configuration("CA file"))?;
        catalog
            .record(stamp)
            .map_err(|_| Error::Configuration("CA file changed"))?;
        let certs = rustls_pemfile::certs(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Configuration("CA encoding"))?;
        if certs.is_empty() {
            return Err(Error::Configuration("empty CA file"));
        }
        for cert in certs {
            roots
                .add(cert)
                .map_err(|_| Error::Configuration("CA certificate"))?;
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Tls)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}
pub(crate) async fn bootstrap(
    host: &str,
    system: &System,
    settings: &Settings,
    context: &OperationContext,
) -> Result<Vec<IpAddr>, Error> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![ip]);
    }
    if let Some(ips) = settings.bootstrap.get(&host.to_ascii_lowercase()) {
        return Ok(ips.clone());
    }
    system.lookup(host, context).await
}
impl Server {
    pub(crate) fn compile(
        item: &DnsResolver,
        catalog: &mut Catalog,
        limits: &route::Limits,
        settings: &Settings,
        system: Arc<System>,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        if !item.extensions.is_empty() {
            return Err(Error::Configuration("DNS extension"));
        }
        let selector = Selectors::compile(&item.domains, catalog, limits, true)
            .map_err(|_| Error::Configuration("DNS selectors"))?;
        let kind = match item.transport.trim().to_ascii_lowercase().as_str() {
            "" | "udp" => Kind::Udp,
            "tcp" => Kind::Tcp,
            "tls" | "dot" => Kind::Tls,
            "https" | "doh" => Kind::Https,
            _ => return Err(Error::Configuration("DNS transport")),
        };
        let address = item.address.trim();
        if address.len() > 8192 || address.is_empty() {
            return Err(Error::Configuration("DNS address"));
        }
        let (mut url, host, port, http_host) = if matches!(kind, Kind::Https) {
            let url = url::Url::parse(address).map_err(|_| Error::Configuration("DoH URL"))?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(Error::Configuration("DoH URL"));
            }
            let host = url
                .host_str()
                .expect("host")
                .trim_matches(['[', ']'])
                .to_owned();
            let authority = url[url::Position::BeforeHost..url::Position::AfterPort].to_owned();
            let port = url
                .port_or_known_default()
                .ok_or(Error::Configuration("DoH port"))?;
            (Some(url), host, port, authority)
        } else {
            let default = if matches!(kind, Kind::Tls) { 853 } else { 53 };
            let stripped = address
                .strip_prefix("udp://")
                .or_else(|| address.strip_prefix("tcp://"))
                .or_else(|| address.strip_prefix("tls://"))
                .unwrap_or(address);
            let parsed = url::Url::parse(&format!("dns://{stripped}"))
                .map_err(|_| Error::Configuration("DNS address"))?;
            if !parsed.username().is_empty()
                || parsed.password().is_some()
                || !matches!(parsed.path(), "" | "/")
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(Error::Configuration("DNS address"));
            }
            let host = parsed
                .host_str()
                .ok_or(Error::Configuration("DNS host"))?
                .trim_matches(['[', ']'])
                .to_owned();
            (None, host, parsed.port().unwrap_or(default), String::new())
        };
        if port == 0 {
            return Err(Error::Configuration("DNS port"));
        }
        let server_name = if item.server_name.trim().is_empty() {
            host.clone()
        } else {
            item.server_name.trim().to_owned()
        };
        if matches!(kind, Kind::Tls | Kind::Https) {
            ServerName::try_from(server_name.clone())
                .map_err(|_| Error::Configuration("TLS server name"))?;
        }
        let client = if let Some(endpoint) = &mut url {
            if !item.server_name.trim().is_empty() {
                if let Ok(ip) = server_name.parse::<IpAddr>() {
                    // reqwest bypasses its DNS resolver for literal URL hosts.
                    // Do not silently dial the certificate override as a new endpoint.
                    if host.parse::<IpAddr>().ok() != Some(ip) {
                        return Err(Error::Configuration(
                            "DoH IP server_name differs from endpoint",
                        ));
                    }
                    endpoint
                        .set_ip_host(ip)
                        .map_err(|_| Error::Configuration("DoH server name"))?;
                } else {
                    endpoint
                        .set_host(Some(&server_name))
                        .map_err(|_| Error::Configuration("DoH server name"))?;
                }
            }
            Some(
                reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(settings.timeout_seconds))
                    .tls_backend_preconfigured((*tls).clone())
                    .dns_resolver(Bootstrap {
                        host: host.clone(),
                        system: system.clone(),
                        settings: settings.clone(),
                    })
                    .build()
                    .map_err(|_| Error::Configuration("DoH client"))?,
            )
        } else {
            None
        };
        Ok(Self {
            selector,
            default: item.domains.iter().all(|value| value.trim().is_empty()),
            kind,
            host,
            port,
            server_name,
            url,
            http_host,
            client,
            tls,
            system,
            settings: settings.clone(),
        })
    }
    async fn endpoints(&self, context: &OperationContext) -> Result<Vec<SocketAddr>, Error> {
        Ok(bootstrap(&self.host, &self.system, &self.settings, context)
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .collect())
    }
    async fn tcp(&self, context: &OperationContext) -> Result<TcpStream, Error> {
        for address in self.endpoints(context).await? {
            if let Ok(stream) = context
                .run(TcpStream::connect(address))
                .await
                .map_err(Error::Stopped)?
            {
                return Ok(stream);
            }
        }
        Err(Error::Transport)
    }
    pub(crate) async fn exchange(
        &self,
        query: &hickory_proto::op::Message,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<(hickory_proto::op::Message, u32), Error> {
        let mut request = query.clone();
        request.metadata.id = if matches!(self.kind, Kind::Https) {
            0
        } else {
            u16::from_le_bytes(random()?)
        };
        let encoded = request.to_vec().map_err(|_| Error::InvalidQuery)?;
        let (mut response, age) = match self.kind {
            Kind::Udp => {
                let address = self
                    .endpoints(context)
                    .await?
                    .into_iter()
                    .next()
                    .ok_or(Error::Transport)?;
                let bind = if address.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = context
                    .run(UdpSocket::bind(bind))
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| Error::Transport)?;
                context
                    .run(socket.connect(address))
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| Error::Transport)?;
                context
                    .run(socket.send(&encoded))
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| Error::Transport)?;
                let mut buffer = scope
                    .try_lease(BufferLayout::new(0, 65536, 0).map_err(|_| Error::Capacity)?)
                    .map_err(|_| Error::Capacity)?;
                buffer.append_zeroed(65536).map_err(|_| Error::Capacity)?;
                let mut found = None;
                for _ in 0..16 {
                    let n = context
                        .run(socket.recv(buffer.as_mut_slice()))
                        .await
                        .map_err(Error::Stopped)?
                        .map_err(|_| Error::Transport)?;
                    if n < 12
                        || u16::from_be_bytes([buffer.as_slice()[0], buffer.as_slice()[1]])
                            != request.metadata.id
                    {
                        continue;
                    }
                    let Ok(response) = wire::parse(&buffer.as_slice()[..n]) else {
                        continue;
                    };
                    if wire::validate(&request, &response).is_err() {
                        continue;
                    }
                    found = Some(response);
                    break;
                }
                let response = found.ok_or(Error::InvalidResponse)?;
                if response.metadata.truncation {
                    (self.stream(&encoded, false, scope, context).await?, 0)
                } else {
                    (response, 0)
                }
            }
            Kind::Tcp => (self.stream(&encoded, false, scope, context).await?, 0),
            Kind::Tls => (self.stream(&encoded, true, scope, context).await?, 0),
            Kind::Https => {
                let mut response = context
                    .run(
                        self.client
                            .as_ref()
                            .expect("DoH client")
                            .post(self.url.clone().expect("DoH URL"))
                            .header(reqwest::header::HOST, &self.http_host)
                            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
                            .header(reqwest::header::ACCEPT, "application/dns-message")
                            .body(encoded)
                            .send(),
                    )
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| Error::Transport)?;
                if response.status() != reqwest::StatusCode::OK {
                    return Err(Error::HttpStatus(response.status().as_u16()));
                }
                if response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.split(';').next())
                    .map(str::trim)
                    != Some("application/dns-message")
                {
                    return Err(Error::InvalidResponse);
                }
                if response
                    .content_length()
                    .is_some_and(|n| n > wire::MAX_WIRE as u64)
                {
                    return Err(Error::TooLarge);
                }
                let age = response
                    .headers()
                    .get(reqwest::header::AGE)
                    .map(|v| {
                        v.to_str()
                            .ok()
                            .and_then(|v| v.parse::<u32>().ok())
                            .ok_or(Error::InvalidResponse)
                    })
                    .transpose()?
                    .unwrap_or(0);
                let mut buffer = scope
                    .try_lease(
                        BufferLayout::new(0, wire::MAX_WIRE, 0).map_err(|_| Error::Capacity)?,
                    )
                    .map_err(|_| Error::Capacity)?;
                while let Some(chunk) = context
                    .run(response.chunk())
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| Error::Transport)?
                {
                    buffer.append_payload(&chunk).map_err(|_| Error::TooLarge)?;
                }
                (wire::parse(buffer.as_slice())?, age)
            }
        };
        wire::validate(&request, &response)?;
        if response.metadata.truncation {
            return Err(Error::InvalidResponse);
        }
        wire::age(&mut response, age);
        response.metadata.id = 0;
        Ok((response, age))
    }
    async fn stream(
        &self,
        encoded: &[u8],
        tls: bool,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<hickory_proto::op::Message, Error> {
        let stream = self.tcp(context).await?;
        if tls {
            let connection = tokio_rustls::TlsConnector::from(self.tls.clone());
            let mut stream = context
                .run(connection.connect(
                    ServerName::try_from(self.server_name.clone()).map_err(|_| Error::Tls)?,
                    stream,
                ))
                .await
                .map_err(Error::Stopped)?
                .map_err(|_| Error::Tls)?;
            stream_exchange(&mut stream, encoded, scope, context).await
        } else {
            let mut stream = stream;
            stream_exchange(&mut stream, encoded, scope, context).await
        }
    }
}
async fn stream_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    query: &[u8],
    scope: &BufferScope,
    context: &OperationContext,
) -> Result<hickory_proto::op::Message, Error> {
    context
        .run(async {
            stream
                .write_all(&(query.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(query).await?;
            stream.flush().await
        })
        .await
        .map_err(Error::Stopped)?
        .map_err(|_: std::io::Error| Error::Transport)?;
    let length = context
        .run(stream.read_u16())
        .await
        .map_err(Error::Stopped)?
        .map_err(|_| Error::Transport)? as usize;
    if length < 12 {
        return Err(Error::InvalidResponse);
    }
    let mut buffer = scope
        .try_lease(BufferLayout::new(0, length, 0).map_err(|_| Error::Capacity)?)
        .map_err(|_| Error::Capacity)?;
    buffer.append_zeroed(length).map_err(|_| Error::Capacity)?;
    context
        .run(stream.read_exact(buffer.as_mut_slice()))
        .await
        .map_err(Error::Stopped)?
        .map_err(|_| Error::Transport)?;
    wire::parse(buffer.as_slice())
}
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| Error::Transport)?;
    Ok(bytes)
}
