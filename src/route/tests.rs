// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use geodata::{Assets, Catalog};
fn selectors(values: &[&str]) -> Selectors {
    Selectors::compile(
        &values.iter().map(|v| (*v).into()).collect::<Vec<_>>(),
        &mut Catalog::new(Assets::default()),
        &Limits::default(),
        false,
    )
    .unwrap()
}
#[test]
fn domain_modes_preserve_label_boundaries_and_case() {
    let exact = selectors(&["full:Example.TEST"]);
    assert!(exact.domain("example.test."));
    assert!(!exact.domain("sub.example.test"));
    let suffix = selectors(&["domain:example.test"]);
    assert!(suffix.domain("sub.EXAMPLE.test"));
    assert!(suffix.domain("example.test"));
    assert!(!suffix.domain("badexample.test"));
    let keyword = selectors(&["keyword:needle"]);
    assert!(keyword.domain("myneedle.test"));
    let regex = selectors(&[r"regexp:^api[0-9]+\.test$"]);
    assert!(regex.domain("API42.test"));
    assert!(!regex.domain("x.api42.test"));
    assert!(selectors(&["bare.test"]).domain("bare.test"));
}
#[test]
fn ipv4_ipv6_and_mapped_prefixes_match_after_compaction() {
    let set = selectors(&[
        "127.0.0.0/8",
        "127.0.0.1/32",
        "::1/128",
        "::ffff:10.0.0.0/104",
    ]);
    for ip in ["127.2.3.4", "::ffff:127.2.3.4", "::1", "10.2.3.4"] {
        assert!(set.ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["128.0.0.1", "::2", "11.0.0.1"] {
        assert!(!set.ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(selectors(&["0.0.0.0/0"]).ip("255.255.255.255".parse().unwrap()));
    assert!(selectors(&["::/0"]).ip("ffff::1".parse().unwrap()));
}
#[test]
fn invalid_and_aggregate_rule_limits_reject_candidate() {
    for value in [
        "geosite:missing",
        "geoip:missing",
        "wat:hello",
        "regex:(",
        "domain:a..test",
        "256.0.0.1/33",
    ] {
        assert!(
            Selectors::compile(
                &[value.into()],
                &mut Catalog::new(Assets::default()),
                &Limits::default(),
                false
            )
            .is_err()
        );
    }
    let limits = Limits {
        max_selectors: 2,
        ..Default::default()
    };
    let mut catalog = Catalog::new(Assets::default());
    Selectors::compile(
        &["a.test".into(), "b.test".into()],
        &mut catalog,
        &limits,
        false,
    )
    .unwrap();
    assert!(Selectors::compile(&["c.test".into()], &mut catalog, &limits, false).is_err());
    assert!(selectors(&["geoip:private"]).ip("127.0.0.1".parse().unwrap()));
}
