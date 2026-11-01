// SPDX-License-Identifier: GPL-3.0-only

use super::convert::config_value;
use super::dto_config::*;
use crate::panel::{self, ConfigValue, Endpoint, Error, ProtocolName, Result, Secret};
use std::collections::BTreeMap;

impl TryFrom<DnsDto> for panel::DnsResolver {
    type Error = Error;
    fn try_from(dto: DnsDto) -> Result<Self> {
        Ok(Self {
            transport: dto.proto,
            address: dto.address,
            server_name: dto.server_name,
            domains: dto.domains,
            extensions: extensions(dto.extensions),
        })
    }
}

impl TryFrom<OutboundDto> for panel::Outbound {
    type Error = Error;
    fn try_from(dto: OutboundDto) -> Result<Self> {
        Ok(Self {
            name: dto.name,
            protocol: ProtocolName::new(&dto.protocol)
                .map_err(|_| Error::schema(Endpoint::Config, "invalid protocol name"))?,
            address: dto.address,
            port: u16::try_from(dto.port)
                .map_err(|_| Error::schema(Endpoint::Config, "port out of range"))?,
            user: dto.user,
            password: Secret::new(dto.password),
            uuid: Secret::new(dto.uuid),
            cipher: dto.cipher,
            plugin: dto.plugin,
            plugin_options: plugin_options(dto.plugin_options)?,
            security: dto.security,
            sni: dto.sni,
            alpn: dto.alpn,
            allow_insecure: dto.allow_insecure,
            fingerprint: dto.fingerprint,
            transport: dto.transport,
            host: dto.host,
            path: dto.path,
            service_name: dto.service_name,
            xhttp_mode: dto.xhttp_mode,
            xhttp_extra: dto.xhttp_extra,
            flow: dto.flow,
            encryption: dto.encryption,
            encryption_mode: dto.encryption_mode,
            encryption_rtt: dto.encryption_rtt,
            encryption_ticket: Secret::new(dto.encryption_ticket),
            encryption_client_padding: dto.encryption_client_padding,
            encryption_password: Secret::new(dto.encryption_password),
            multiplex: dto.multiplex,
            uot: dto.uot,
            uot_version: u64::try_from(dto.uot_version)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            congestion_controller: dto.congestion_controller,
            udp_stream: dto.udp_stream,
            reduce_rtt: dto.reduce_rtt,
            heartbeat: u64::try_from(dto.heartbeat)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            reality_public_key: dto.reality_public_key,
            reality_short_id: dto.reality_short_id,
            spider_x: dto.spider_x,
            settings: dto.settings,
            stream_settings: dto.stream_settings,
            rules: dto.rules,
            extensions: extensions(dto.extensions),
        })
    }
}

impl TryFrom<ProtocolDto> for panel::ProtocolConfig {
    type Error = Error;
    fn try_from(dto: ProtocolDto) -> Result<Self> {
        if dto.enable && dto.port == 0 {
            return Err(Error::schema(
                Endpoint::Config,
                "enabled protocol requires a port",
            ));
        }
        if !dto.ratio.is_finite() || dto.ratio < 0.0 {
            return Err(Error::schema(Endpoint::Config, "invalid traffic ratio"));
        }
        Ok(Self {
            protocol: ProtocolName::new(&dto.kind)
                .map_err(|_| Error::schema(Endpoint::Config, "invalid protocol name"))?,
            port: u16::try_from(dto.port)
                .map_err(|_| Error::schema(Endpoint::Config, "port out of range"))?,
            version: u64::try_from(dto.version)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            mode: dto.mode,
            enabled: dto.enable,
            security: dto.security,
            network: dto.network,
            sni: dto.sni,
            alpn: dto.alpn,
            allow_insecure: dto.allow_insecure,
            fingerprint: dto.fingerprint,
            reality_server_addr: dto.reality_server_addr,
            reality_server_port: u16::try_from(dto.reality_server_port)
                .map_err(|_| Error::schema(Endpoint::Config, "port out of range"))?,
            reality_private_key: Secret::new(dto.reality_private_key),
            reality_public_key: dto.reality_public_key,
            reality_short_id: dto.reality_short_id,
            transport: dto.transport,
            host: dto.host,
            path: dto.path,
            service_name: dto.service_name,
            cipher: dto.cipher,
            server_key: Secret::new(dto.server_key),
            plugin: dto.plugin,
            plugin_options: plugin_options(dto.plugin_options)?,
            flow: dto.flow,
            uot: dto.uot,
            uot_version: u64::try_from(dto.uot_version)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            accept_proxy_protocol: dto.accept_proxy_protocol,
            hop_ports: dto.hop_ports,
            hop_interval: u64::try_from(dto.hop_interval)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            obfs_password: Secret::new(dto.obfs_password),
            disable_sni: dto.disable_sni,
            reduce_rtt: dto.reduce_rtt,
            heartbeat: u64::try_from(dto.heartbeat)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            udp_relay_mode: dto.udp_relay_mode,
            congestion_controller: dto.congestion_controller,
            quic_congestion_control: dto.quic_congestion_control,
            multiplex: dto.multiplex,
            padding_scheme: dto.padding_scheme,
            traffic_pattern: dto.traffic_pattern,
            user_hint_is_mandatory: dto.user_hint_is_mandatory,
            up_mbps: u64::try_from(dto.up_mbps)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            down_mbps: u64::try_from(dto.down_mbps)
                .map_err(|_| Error::schema(Endpoint::Config, "negative protocol parameter"))?,
            obfs: dto.obfs,
            ssr_protocol: dto.ssr_protocol,
            protocol_param: dto.protocol_param,
            obfs_param: dto.obfs_param,
            obfs_host: dto.obfs_host,
            obfs_path: dto.obfs_path,
            xhttp_mode: dto.xhttp_mode,
            xhttp_extra: dto.xhttp_extra,
            encryption: dto.encryption,
            encryption_mode: dto.encryption_mode,
            encryption_rtt: dto.encryption_rtt,
            encryption_ticket: Secret::new(dto.encryption_ticket),
            encryption_server_padding: dto.encryption_server_padding,
            encryption_private_key: Secret::new(dto.encryption_private_key),
            encryption_client_padding: dto.encryption_client_padding,
            encryption_password: Secret::new(dto.encryption_password),
            ech_enable: dto.ech_enable,
            ech_server_name: dto.ech_server_name,
            ratio: dto.ratio,
            cert_mode: dto.cert_mode,
            cert_dns_provider: dto.cert_dns_provider,
            cert_dns_env: Secret::new(dto.cert_dns_env),
            extensions: extensions(dto.extensions),
        })
    }
}

pub(super) fn extensions(
    values: BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, ConfigValue> {
    values
        .into_iter()
        .map(|(key, value)| (key, config_value(value)))
        .collect()
}

fn plugin_options(value: serde_json::Value) -> Result<ConfigValue> {
    if !value.is_null() && !value.is_string() && !value.is_object() {
        return Err(Error::schema(
            Endpoint::Config,
            "plugin options must be an object or string",
        ));
    }
    Ok(config_value(value))
}
