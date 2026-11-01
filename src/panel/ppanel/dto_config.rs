// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn nullable_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize)]
pub(super) struct DnsDto {
    pub proto: String,
    pub address: String,
    #[serde(default)]
    pub server_name: String,
    #[serde(default, deserialize_with = "nullable_vec")]
    pub domains: Vec<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
pub(super) struct OutboundDto {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: i64,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub plugin: String,
    #[serde(rename = "plugin_opts", default)]
    pub plugin_options: Value,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default, deserialize_with = "nullable_vec")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub xhttp_mode: String,
    #[serde(default)]
    pub xhttp_extra: String,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub encryption: String,
    #[serde(default)]
    pub encryption_mode: String,
    #[serde(default)]
    pub encryption_rtt: String,
    #[serde(default)]
    pub encryption_ticket: String,
    #[serde(default)]
    pub encryption_client_padding: String,
    #[serde(default)]
    pub encryption_password: String,
    #[serde(default)]
    pub multiplex: String,
    #[serde(default)]
    pub uot: bool,
    #[serde(default)]
    pub uot_version: i64,
    #[serde(default)]
    pub congestion_controller: String,
    #[serde(default)]
    pub udp_stream: bool,
    #[serde(default)]
    pub reduce_rtt: bool,
    #[serde(default)]
    pub heartbeat: i64,
    #[serde(default)]
    pub reality_public_key: String,
    #[serde(default)]
    pub reality_short_id: String,
    #[serde(default)]
    pub spider_x: String,
    #[serde(default)]
    pub settings: String,
    #[serde(default)]
    pub stream_settings: String,
    #[serde(default, deserialize_with = "nullable_vec")]
    pub rules: Vec<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
pub(super) struct ProtocolDto {
    #[serde(rename = "type")]
    pub kind: String,
    pub port: u32,
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub mode: String,
    pub enable: bool,
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default, deserialize_with = "nullable_vec")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub reality_server_addr: String,
    #[serde(default)]
    pub reality_server_port: i64,
    #[serde(default)]
    pub reality_private_key: String,
    #[serde(default)]
    pub reality_public_key: String,
    #[serde(default)]
    pub reality_short_id: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub server_key: String,
    #[serde(default)]
    pub plugin: String,
    #[serde(rename = "plugin_opts", default)]
    pub plugin_options: Value,
    #[serde(default)]
    pub flow: String,
    #[serde(default)]
    pub uot: bool,
    #[serde(default)]
    pub uot_version: i64,
    #[serde(default)]
    pub accept_proxy_protocol: bool,
    #[serde(default)]
    pub hop_ports: String,
    #[serde(default)]
    pub hop_interval: i64,
    #[serde(default)]
    pub obfs_password: String,
    #[serde(default)]
    pub disable_sni: bool,
    #[serde(default)]
    pub reduce_rtt: bool,
    #[serde(default)]
    pub heartbeat: i64,
    #[serde(default)]
    pub udp_relay_mode: String,
    #[serde(default)]
    pub congestion_controller: String,
    #[serde(default)]
    pub quic_congestion_control: String,
    #[serde(default)]
    pub multiplex: String,
    #[serde(default)]
    pub padding_scheme: String,
    #[serde(default)]
    pub traffic_pattern: String,
    #[serde(default)]
    pub user_hint_is_mandatory: bool,
    #[serde(default)]
    pub up_mbps: i64,
    #[serde(default)]
    pub down_mbps: i64,
    #[serde(default)]
    pub obfs: String,
    #[serde(rename = "protocol", default)]
    pub ssr_protocol: String,
    #[serde(default)]
    pub protocol_param: String,
    #[serde(default)]
    pub obfs_param: String,
    #[serde(default)]
    pub obfs_host: String,
    #[serde(default)]
    pub obfs_path: String,
    #[serde(default)]
    pub xhttp_mode: String,
    #[serde(default)]
    pub xhttp_extra: String,
    #[serde(default)]
    pub encryption: String,
    #[serde(default)]
    pub encryption_mode: String,
    #[serde(default)]
    pub encryption_rtt: String,
    #[serde(default)]
    pub encryption_ticket: String,
    #[serde(default)]
    pub encryption_server_padding: String,
    #[serde(default)]
    pub encryption_private_key: String,
    #[serde(default)]
    pub encryption_client_padding: String,
    #[serde(default)]
    pub encryption_password: String,
    #[serde(default)]
    pub ech_enable: bool,
    #[serde(default)]
    pub ech_server_name: String,
    #[serde(default)]
    pub ratio: f64,
    #[serde(default)]
    pub cert_mode: String,
    #[serde(default)]
    pub cert_dns_provider: String,
    #[serde(default)]
    pub cert_dns_env: String,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}
