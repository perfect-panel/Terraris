// SPDX-License-Identifier: GPL-3.0-only
use super::encryption;
use crate::{panel::ProtocolConfig, resource, runtime::Error, time::Deadline};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
#[derive(Clone, Debug)]
pub struct Options {
    pub listen: IpAddr,
    pub allow_plaintext: bool,
    pub max_connections: usize,
    pub max_handshakes: usize,
    pub connection_buffers: resource::Limits,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub max_xudp_sessions: usize,
    pub queue_packets: usize,
    pub encryption_limits: encryption::Limits,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            listen: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            allow_plaintext: false,
            max_connections: 4096,
            max_handshakes: 128,
            connection_buffers: resource::Limits::new(4 << 20, 256).expect("fixed limits"),
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            udp_idle_timeout: Duration::from_secs(60),
            max_xudp_sessions: 32,
            queue_packets: 32,
            encryption_limits: encryption::Limits::default(),
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_connections == 0
            || self.max_handshakes == 0
            || self.max_handshakes > self.max_connections
            || self.max_xudp_sessions == 0
            || self.max_xudp_sessions > 1024
            || self.queue_packets == 0
            || self.queue_packets > 1024
            || self.connection_buffers.bytes() < 262144
            || self.connection_buffers.allocations() < 8
        {
            return Err(Error::Preparation("VLESS resource limits"));
        }
        for duration in [
            self.handshake_timeout,
            self.idle_timeout,
            self.udp_idle_timeout,
        ] {
            if duration.is_zero() || Deadline::after(duration).is_err() {
                return Err(Error::Preparation("VLESS timeout"));
            }
        }
        Ok(())
    }
}
pub(super) fn validate(
    config: &ProtocolConfig,
    options: &Options,
) -> Result<Option<encryption::Config>, Error> {
    if config.protocol.as_str() != "vless"
        || config.port == 0
        || !matches!(config.network.as_str(), "" | "tcp" | "raw")
        || !matches!(config.transport.as_str(), "" | "tcp" | "raw")
        || !matches!(config.security.as_str(), "" | "none")
        || !matches!(config.cert_mode.as_str(), "" | "none")
    {
        return Err(Error::Unsupported);
    }
    reject_extra(config)?;
    let encryption = encryption::Config::from_panel(config)
        .map_err(|_| Error::Preparation("VLESS encryption settings"))?;
    if encryption.is_none() && !options.allow_plaintext && !options.listen.is_loopback() {
        return Err(Error::Preparation(
            "unencrypted VLESS requires trusted local transport or explicit allow_plaintext",
        ));
    }
    Ok(encryption)
}

fn reject_extra(config: &ProtocolConfig) -> Result<(), Error> {
    if config.version != 0
        || !config.mode.is_empty()
        || !config.sni.is_empty()
        || !config.alpn.is_empty()
        || config.allow_insecure
        || !config.fingerprint.is_empty()
        || !config.reality_server_addr.is_empty()
        || config.reality_server_port != 0
        || !config.reality_private_key.expose().is_empty()
        || !config.reality_public_key.is_empty()
        || !config.reality_short_id.is_empty()
        || !config.host.is_empty()
        || !config.path.is_empty()
        || !config.service_name.is_empty()
        || !config.cipher.is_empty()
        || !config.server_key.expose().is_empty()
        || !config.plugin.is_empty()
        || config.plugin_options != crate::panel::ConfigValue::Null
        || !config.flow.is_empty()
        || config.uot
        || config.uot_version != 0
        || config.accept_proxy_protocol
        || !config.hop_ports.is_empty()
        || config.hop_interval != 0
        || !config.obfs_password.expose().is_empty()
        || config.disable_sni
        || config.reduce_rtt
        || config.heartbeat != 0
        || !config.udp_relay_mode.is_empty()
        || !config.congestion_controller.is_empty()
        || !config.quic_congestion_control.is_empty()
        || !config.multiplex.is_empty()
        || !config.padding_scheme.is_empty()
        || !config.traffic_pattern.is_empty()
        || config.user_hint_is_mandatory
        || config.up_mbps != 0
        || config.down_mbps != 0
        || !config.obfs.is_empty()
        || !config.ssr_protocol.is_empty()
        || !config.protocol_param.is_empty()
        || !config.obfs_param.is_empty()
        || !config.obfs_host.is_empty()
        || !config.obfs_path.is_empty()
        || !config.xhttp_mode.is_empty()
        || !config.xhttp_extra.is_empty()
        || config.ech_enable
        || !config.ech_server_name.is_empty()
        || !config.cert_dns_provider.is_empty()
        || !config.cert_dns_env.expose().is_empty()
        || !config.extensions.is_empty()
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
