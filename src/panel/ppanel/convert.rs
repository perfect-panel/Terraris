// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::{BTreeMap, HashSet},
    time::Duration,
};

use prost::Message;
use serde::Deserialize;
use serde_json::Value;

use super::{
    dto_config::{DnsDto, OutboundDto, ProtocolDto, nullable_vec},
    normalize_config::extensions,
    wire,
};
use crate::panel::{
    ConfigValue, DeviceClaim, Encoding, Endpoint, Error, ErrorKind, Result, Secret, ServerConfig,
    SubscriptionId, User,
};

#[derive(Deserialize)]
struct Envelope<T> {
    code: u32,
    data: Option<T>,
}

#[derive(Deserialize)]
struct ConfigDto {
    traffic_report_threshold: i64,
    push_interval: i64,
    pull_interval: i64,
    ip_strategy: String,
    #[serde(deserialize_with = "nullable_vec")]
    dns: Vec<DnsDto>,
    #[serde(deserialize_with = "nullable_vec")]
    block: Vec<String>,
    #[serde(deserialize_with = "nullable_vec")]
    outbound: Vec<OutboundDto>,
    #[serde(deserialize_with = "nullable_vec")]
    protocols: Vec<ProtocolDto>,
    total: i64,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}

fn json<T: serde::de::DeserializeOwned>(endpoint: Endpoint, body: &[u8]) -> Result<T> {
    serde_json::from_slice(body)
        .map_err(|_| Error::new(endpoint, ErrorKind::Decode, "invalid JSON response"))
}

fn protobuf<T: Message + Default>(endpoint: Endpoint, body: &[u8]) -> Result<T> {
    T::decode(body)
        .map_err(|_| Error::new(endpoint, ErrorKind::Decode, "invalid Protobuf response"))
}

fn success(endpoint: Endpoint, code: u32) -> Result<()> {
    if code != 200 {
        return Err(Error::business(endpoint, code));
    }
    Ok(())
}

fn present<T>(endpoint: Endpoint, value: Option<T>) -> Result<T> {
    value.ok_or_else(|| Error::schema(endpoint, "required response data is missing"))
}

pub(super) fn config(body: &[u8], encoding: Encoding) -> Result<ServerConfig> {
    let endpoint = Endpoint::Config;
    let dto = match encoding {
        Encoding::Json => {
            let result: Envelope<ConfigDto> = json(endpoint, body)?;
            success(endpoint, result.code)?;
            present(endpoint, result.data)?
        }
        Encoding::Protobuf => {
            let result: wire::QueryServerProtocolConfigResponse = protobuf(endpoint, body)?;
            success(endpoint, result.code)?;
            let data = present(endpoint, result.data)?;
            ConfigDto {
                traffic_report_threshold: data.traffic_report_threshold,
                push_interval: data.push_interval,
                pull_interval: data.pull_interval,
                ip_strategy: data.ip_strategy,
                block: data.block,
                total: data.total,
                dns: data
                    .dns
                    .into_iter()
                    .map(DnsDto::from_proto)
                    .collect::<Result<_>>()?,
                outbound: data
                    .outbound
                    .into_iter()
                    .map(OutboundDto::from_proto)
                    .collect::<Result<_>>()?,
                protocols: data
                    .protocols
                    .into_iter()
                    .map(ProtocolDto::from_proto)
                    .collect::<Result<_>>()?,
                extensions: Default::default(),
            }
        }
    };
    if usize::try_from(dto.total).ok() != Some(dto.protocols.len()) {
        return Err(Error::schema(
            endpoint,
            "protocol count does not match configuration",
        ));
    }
    let config = ServerConfig {
        // Compatibility with the current node: non-positive intervals mean 60s.
        pull_interval: interval(dto.pull_interval),
        push_interval: interval(dto.push_interval),
        traffic_report_threshold: dto.traffic_report_threshold.max(0) as u64,
        ip_strategy: dto.ip_strategy,
        block: dto.block,
        dns: dto
            .dns
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?,
        outbounds: dto
            .outbound
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?,
        protocols: dto
            .protocols
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_>>()?,
        extensions: extensions(dto.extensions),
    };
    let mut names = HashSet::new();
    for protocol in &config.protocols {
        if !names.insert(&protocol.protocol) {
            return Err(Error::schema(endpoint, "duplicate protocol"));
        }
    }
    Ok(config)
}

fn interval(seconds: i64) -> Duration {
    Duration::from_secs(if seconds <= 0 { 60 } else { seconds as u64 })
}

#[derive(Deserialize)]
struct UsersDto {
    code: Option<u32>,
    users: Option<Vec<UserDto>>,
}

#[derive(Deserialize)]
struct UserDto {
    id: i64,
    uuid: String,
    speed_limit: i64,
    device_limit: i64,
}

pub(super) fn users(body: &[u8], encoding: Encoding) -> Result<Vec<User>> {
    let endpoint = Endpoint::Users;
    let records = match encoding {
        Encoding::Json => {
            let result: UsersDto = json(endpoint, body)?;
            if let Some(code) = result.code {
                success(endpoint, code)?;
            }
            present(endpoint, result.users)?
        }
        Encoding::Protobuf => {
            let result: wire::GetServerUserListResponse = protobuf(endpoint, body)?;
            success(endpoint, result.code)?;
            present(endpoint, result.data)?
                .users
                .into_iter()
                .map(|u| UserDto {
                    id: u.id,
                    uuid: u.uuid,
                    speed_limit: u.speed_limit,
                    device_limit: u.device_limit,
                })
                .collect()
        }
    };
    let mut ids = HashSet::with_capacity(records.len());
    let mut credentials = HashSet::with_capacity(records.len());
    let mut users = Vec::with_capacity(records.len());
    for record in records {
        if record.id <= 0
            || record.uuid.is_empty()
            || record.uuid.len() > 4096
            || record.speed_limit < 0
            || record.device_limit < 0
        {
            return Err(Error::schema(
                endpoint,
                "invalid user identity, credential or limits",
            ));
        }
        if !ids.insert(record.id) || !credentials.insert(record.uuid.clone()) {
            return Err(Error::schema(endpoint, "duplicate user ID or credential"));
        }
        users.push(User {
            id: SubscriptionId::new(record.id)?,
            credential: Secret::new(record.uuid),
            speed_limit_mbps: record.speed_limit as u64,
            device_limit: record.device_limit as u64,
        });
    }
    Ok(users)
}

#[derive(Deserialize)]
struct AliveDto {
    code: Option<u32>,
    alive: Option<BTreeMap<String, i64>>,
}

pub(super) fn alive(body: &[u8], encoding: Encoding) -> Result<BTreeMap<SubscriptionId, u64>> {
    let endpoint = Endpoint::Alive;
    let values = match encoding {
        Encoding::Json => {
            let result: AliveDto = json(endpoint, body)?;
            if let Some(code) = result.code {
                success(endpoint, code)?;
            }
            let mut values = BTreeMap::new();
            for (key, value) in present(endpoint, result.alive)? {
                let id = key
                    .parse::<i64>()
                    .map_err(|_| Error::schema(endpoint, "invalid alive subscription ID"))?;
                if values.insert(id, value).is_some() {
                    return Err(Error::schema(endpoint, "duplicate alive subscription ID"));
                }
            }
            values
        }
        Encoding::Protobuf => {
            let result: wire::GetServerAliveListResponse = protobuf(endpoint, body)?;
            success(endpoint, result.code)?;
            present(endpoint, result.data)?.alive
        }
    };
    values
        .into_iter()
        .map(|(id, count)| {
            if id <= 0 || count < 0 {
                return Err(Error::schema(endpoint, "invalid alive count"));
            }
            Ok((SubscriptionId::new(id)?, count as u64))
        })
        .collect()
}

#[derive(Deserialize)]
struct ClaimDto {
    code: Option<u32>,
    allowed: Option<bool>,
    ttl_seconds: Option<i64>,
}

pub(super) fn claim(body: &[u8], encoding: Encoding) -> Result<DeviceClaim> {
    let endpoint = Endpoint::Device;
    let (allowed, ttl) = match encoding {
        Encoding::Json => {
            let result: ClaimDto = json(endpoint, body)?;
            if let Some(code) = result.code {
                success(endpoint, code)?;
            }
            (
                present(endpoint, result.allowed)?,
                present(endpoint, result.ttl_seconds)?,
            )
        }
        Encoding::Protobuf => {
            let result: wire::ClaimServerDeviceResponse = protobuf(endpoint, body)?;
            success(endpoint, result.code)?;
            let data = present(endpoint, result.data)?;
            (data.allowed, data.ttl_seconds)
        }
    };
    if ttl <= 0 {
        return Err(Error::schema(endpoint, "device lease TTL must be positive"));
    }
    Ok(DeviceClaim {
        allowed,
        ttl: Duration::from_secs(ttl as u64),
    })
}

#[derive(Deserialize)]
struct ResultDto {
    code: u32,
}

pub(super) fn report(endpoint: Endpoint, body: &[u8], encoding: Encoding) -> Result<()> {
    let code = match encoding {
        Encoding::Json => json::<ResultDto>(endpoint, body)?.code,
        Encoding::Protobuf => protobuf::<wire::Result>(endpoint, body)?.code,
    };
    success(endpoint, code)
}

pub(super) fn config_value(value: Value) -> ConfigValue {
    match value {
        Value::Null => ConfigValue::Null,
        Value::Bool(v) => ConfigValue::Bool(v),
        Value::String(v) => ConfigValue::String(v),
        Value::Array(v) => ConfigValue::Array(v.into_iter().map(config_value).collect()),
        Value::Object(v) => {
            ConfigValue::Object(v.into_iter().map(|(k, v)| (k, config_value(v))).collect())
        }
        Value::Number(v) => {
            if let Some(n) = v.as_i64() {
                ConfigValue::Integer(n)
            } else if let Some(n) = v.as_u64() {
                ConfigValue::Unsigned(n)
            } else {
                let n = v.as_f64().expect("JSON numbers are finite");
                if n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0 {
                    ConfigValue::Integer(n as i64)
                } else {
                    ConfigValue::Float(n)
                }
            }
        }
    }
}

pub(super) fn proto_value(value: Option<prost_types::Value>) -> Result<Value> {
    use prost_types::value::Kind;
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    Ok(match value.kind {
        Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::BoolValue(v)) => Value::Bool(v),
        Some(Kind::StringValue(v)) => Value::String(v),
        Some(Kind::NumberValue(v)) => Value::Number(
            serde_json::Number::from_f64(v)
                .ok_or_else(|| Error::schema(Endpoint::Config, "non-finite plugin option"))?,
        ),
        Some(Kind::ListValue(v)) => Value::Array(
            v.values
                .into_iter()
                .map(|v| proto_value(Some(v)))
                .collect::<Result<_>>()?,
        ),
        Some(Kind::StructValue(v)) => Value::Object(
            v.fields
                .into_iter()
                .map(|(k, v)| Ok((k, proto_value(Some(v))?)))
                .collect::<Result<_>>()?,
        ),
        None => {
            return Err(Error::schema(
                Endpoint::Config,
                "missing plugin option value",
            ));
        }
    })
}
