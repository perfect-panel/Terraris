// SPDX-License-Identifier: GPL-3.0-only

use super::{ConfigValue, ProtocolName, Secret};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, PartialEq)]
pub struct DnsResolver {
    pub transport: String,
    pub address: String,
    pub server_name: String,
    pub domains: Vec<String>,
    pub extensions: BTreeMap<String, ConfigValue>,
}

impl fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DnsResolver([redacted configuration])")
    }
}

#[derive(Clone, PartialEq)]
pub struct Outbound {
    pub name: String,
    pub protocol: ProtocolName,
    pub address: String,
    pub port: u16,
    pub user: String,
    pub password: Secret,
    pub uuid: Secret,
    pub cipher: String,
    pub plugin: String,
    pub plugin_options: ConfigValue,
    pub security: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub fingerprint: String,
    pub transport: String,
    pub host: String,
    pub path: String,
    pub service_name: String,
    pub xhttp_mode: String,
    pub xhttp_extra: String,
    pub flow: String,
    pub encryption: String,
    pub encryption_mode: String,
    pub encryption_rtt: String,
    pub encryption_ticket: Secret,
    pub encryption_client_padding: String,
    pub encryption_password: Secret,
    pub multiplex: String,
    pub uot: bool,
    pub uot_version: u64,
    pub congestion_controller: String,
    pub udp_stream: bool,
    pub reduce_rtt: bool,
    pub heartbeat: u64,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub spider_x: String,
    pub settings: String,
    pub stream_settings: String,
    pub rules: Vec<String>,
    pub extensions: BTreeMap<String, ConfigValue>,
}

impl fmt::Debug for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Outbound([redacted configuration])")
    }
}

#[derive(Clone, PartialEq)]
pub struct ProtocolConfig {
    pub protocol: ProtocolName,
    pub port: u16,
    pub version: u64,
    pub mode: String,
    pub enabled: bool,
    pub security: String,
    pub network: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub fingerprint: String,
    pub reality_server_addr: String,
    pub reality_server_port: u16,
    pub reality_private_key: Secret,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub transport: String,
    pub host: String,
    pub path: String,
    pub service_name: String,
    pub cipher: String,
    pub server_key: Secret,
    pub plugin: String,
    pub plugin_options: ConfigValue,
    pub flow: String,
    pub uot: bool,
    pub uot_version: u64,
    pub accept_proxy_protocol: bool,
    pub hop_ports: String,
    pub hop_interval: u64,
    pub obfs_password: Secret,
    pub disable_sni: bool,
    pub reduce_rtt: bool,
    pub heartbeat: u64,
    pub udp_relay_mode: String,
    pub congestion_controller: String,
    pub quic_congestion_control: String,
    pub multiplex: String,
    pub padding_scheme: String,
    pub traffic_pattern: String,
    pub user_hint_is_mandatory: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
    pub obfs: String,
    pub ssr_protocol: String,
    pub protocol_param: String,
    pub obfs_param: String,
    pub obfs_host: String,
    pub obfs_path: String,
    pub xhttp_mode: String,
    pub xhttp_extra: String,
    pub encryption: String,
    pub encryption_mode: String,
    pub encryption_rtt: String,
    pub encryption_ticket: Secret,
    pub encryption_server_padding: String,
    pub encryption_private_key: Secret,
    pub encryption_client_padding: String,
    pub encryption_password: Secret,
    pub ech_enable: bool,
    pub ech_server_name: String,
    pub ratio: f64,
    pub cert_mode: String,
    pub cert_dns_provider: String,
    pub cert_dns_env: Secret,
    pub extensions: BTreeMap<String, ConfigValue>,
}

impl fmt::Debug for ProtocolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtocolConfig([redacted configuration])")
    }
}
