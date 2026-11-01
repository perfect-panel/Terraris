// SPDX-License-Identifier: GPL-3.0-only
use super::Error;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use std::{collections::HashSet, net::IpAddr};
pub const MAX_WIRE: usize = 65535;
pub fn parse(bytes: &[u8]) -> Result<Message, Error> {
    if !(12..=MAX_WIRE).contains(&bytes.len()) {
        return Err(Error::InvalidResponse);
    }
    let count = (4..12)
        .step_by(2)
        .map(|i| u16::from_be_bytes([bytes[i], bytes[i + 1]]) as usize)
        .sum::<usize>();
    if count > 2048 {
        return Err(Error::InvalidResponse);
    }
    Message::from_vec(bytes).map_err(|_| Error::InvalidResponse)
}
pub fn query(bytes: &[u8]) -> Result<Message, Error> {
    let message = parse(bytes).map_err(|_| Error::InvalidQuery)?;
    if message.metadata.message_type != MessageType::Query
        || message.metadata.op_code != OpCode::Query
        || message.queries.len() != 1
        || !message.answers.is_empty()
        || !message.authorities.is_empty()
        || !message.additionals.is_empty()
        || message.signature.is_some()
        || message.queries[0].query_class != DNSClass::IN
        || matches!(
            message.queries[0].query_type,
            RecordType::AXFR | RecordType::IXFR | RecordType::TSIG
        )
    {
        return Err(Error::InvalidQuery);
    }
    if message.edns.as_ref().is_some_and(|e| e.version() != 0) {
        return Err(Error::InvalidQuery);
    }
    Ok(message)
}
pub fn address_query(name: &str, kind: RecordType) -> Result<Message, Error> {
    let mut name = Name::from_ascii(name).map_err(|_| Error::InvalidQuery)?;
    name.set_fqdn(true);
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.queries.push(Query::query(name, kind));
    Ok(query)
}
pub(crate) fn canonical(mut message: Message) -> Result<(Message, Vec<u8>), Error> {
    message.metadata.id = 0;
    message.queries[0].name = message.queries[0].name.to_lowercase();
    message.queries[0].name.set_fqdn(true);
    let bytes = message.to_vec().map_err(|_| Error::InvalidQuery)?;
    Ok((message, bytes))
}
pub(crate) fn validate(request: &Message, response: &Message) -> Result<(), Error> {
    if response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.metadata.id != request.metadata.id
        || response.signature.is_some()
        || response.queries.len() != 1
    {
        return Err(Error::InvalidResponse);
    }
    let a = &request.queries[0];
    let b = &response.queries[0];
    if a.name.to_lowercase() != b.name.to_lowercase()
        || a.query_type != b.query_type
        || a.query_class != b.query_class
    {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}
pub(crate) fn ttl(message: &Message, max_ttl: u32, negative_cap: u32) -> u32 {
    if message.metadata.truncation {
        return 0;
    }
    let negative = message.metadata.response_code == ResponseCode::NXDomain
        || message.metadata.response_code == ResponseCode::NoError
            && !message
                .answers
                .iter()
                .any(|r| r.record_type() == message.queries[0].query_type)
            && message
                .authorities
                .iter()
                .any(|r| matches!(r.data, RData::SOA(_)));
    if negative {
        let name = &message.queries[0].name;
        return message
            .authorities
            .iter()
            .filter_map(|r| match &r.data {
                RData::SOA(soa) if r.name.zone_of(name) => Some(r.ttl.min(soa.minimum)),
                _ => None,
            })
            .min()
            .unwrap_or(0)
            .min(negative_cap)
            .min(max_ttl)
            .min(
                message
                    .answers
                    .iter()
                    .map(|record| record.ttl)
                    .min()
                    .unwrap_or(u32::MAX),
            );
    }
    if message.metadata.response_code != ResponseCode::NoError {
        return 0;
    }
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0)
        .min(max_ttl)
}
pub(crate) fn age(message: &mut Message, seconds: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(&mut message.authorities)
        .chain(&mut message.additionals)
    {
        record.ttl = record.ttl.saturating_sub(seconds);
    }
}
pub fn error_response(query: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.response_code = code;
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.queries = query.queries.clone();
    response
}
pub(crate) fn for_client(
    mut message: Message,
    request: &Message,
    udp: bool,
) -> Result<Vec<u8>, Error> {
    message.metadata.id = request.metadata.id;
    message.queries = request.queries.clone();
    let bytes = message.to_vec().map_err(|_| Error::InvalidResponse)?;
    let limit = if udp {
        request
            .edns
            .as_ref()
            .map_or(512, |e| usize::from(e.max_payload()).clamp(512, 4096))
    } else {
        MAX_WIRE
    };
    if bytes.len() <= limit {
        return Ok(bytes);
    }
    let mut truncated = error_response(request, message.metadata.response_code);
    truncated.metadata.truncation = true;
    truncated.to_vec().map_err(|_| Error::InvalidResponse)
}
/// Extract only addresses owned by the question or its authenticated CNAME
/// chain. Unrelated additional records never become dial destinations.
pub(crate) fn addresses(message: &Message) -> Result<(Vec<IpAddr>, Option<String>), Error> {
    if message.metadata.response_code == ResponseCode::NXDomain {
        return Err(Error::NoRecords);
    }
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(Error::ServerFailure);
    }
    let mut name = message.queries[0].name.to_lowercase();
    let kind = message.queries[0].query_type;
    let mut visited = HashSet::new();
    for _ in 0..16 {
        if !visited.insert(name.clone()) {
            return Err(Error::InvalidResponse);
        }
        let mut ips = Vec::new();
        for record in &message.answers {
            if record.name.to_lowercase() != name || record.dns_class != DNSClass::IN {
                continue;
            }
            match &record.data {
                RData::A(a) if kind == RecordType::A => ips.push(IpAddr::V4(a.0)),
                RData::AAAA(a) if kind == RecordType::AAAA => ips.push(IpAddr::V6(a.0)),
                _ => {}
            }
        }
        if !ips.is_empty() {
            return Ok((ips, None));
        }
        let mut aliases = message.answers.iter().filter_map(|r| {
            if r.name.to_lowercase() == name {
                if let RData::CNAME(value) = &r.data {
                    Some(value.0.to_lowercase())
                } else {
                    None
                }
            } else {
                None
            }
        });
        let Some(next) = aliases.next() else {
            let original = message.queries[0].name.to_lowercase();
            return Ok((vec![], (name != original).then(|| name.to_ascii())));
        };
        if aliases.any(|other| other != next) {
            return Err(Error::InvalidResponse);
        }
        name = next;
    }
    Err(Error::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_addresses_are_not_dial_candidates() {
        let request = address_query("target.test", RecordType::A).unwrap();
        let mut response = error_response(&request, ResponseCode::NoError);
        response.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("attacker.test.").unwrap(),
            60,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::LOCALHOST)),
        ));
        let (ips, alias) = addresses(&response).unwrap();
        assert!(ips.is_empty());
        assert!(alias.is_none());
    }
}
