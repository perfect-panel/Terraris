// SPDX-License-Identifier: GPL-3.0-only

use std::{fs, process::Command};

use terraris::{
    config::Config,
    panel::{Secret, ServerId, ppanel::Options},
};

fn config(extra: &str) -> String {
    format!("[panel]\nbase_url = 'https://panel.example.com/api'\nserver_id = 7\n{extra}\n")
}

#[test]
fn local_check_does_not_require_resolving_secret_source() {
    Config::parse(&config(
        "secret_env = 'TERRARIS_TEST_UNSET_SECRET_VARIABLE' ",
    ))
    .unwrap();
    Config::parse(&config("secret_file = 'missing.secret' ")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_terraris"))
        .args(["check", "--config", "examples/terraris.toml"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("not checked")
    );
}

#[test]
fn secret_files_are_relative_to_config_and_only_trailing_newlines_are_removed() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("node.secret"), "secret with spaces\r\n").unwrap();
    let c = Config::parse(&config("secret_file = 'node.secret'")).unwrap();
    let options = c.connection_options(&dir.path().join("node.toml")).unwrap();
    assert_eq!(options.secret_key.expose(), "secret with spaces");
    assert!(!format!("{options:?}").contains("secret with spaces"));
}

#[test]
fn invalid_config_and_unknown_fields_fail_without_echoing_input() {
    for extra in [
        "",
        "secret_env = 'KEY'\nsecret_file = 'key'",
        "secret_key = 'sensitive-inline-value'",
        "secret_env = 'KEY'\ntimeout_seconds = 0",
        "secret_env = 'KEY'\nwire_format = 'wrong-sensitive-value'",
        "secret_env = 'KEY'\nmax_response_bytes = 0",
    ] {
        let error = Config::parse(&config(extra))
            .err()
            .expect("invalid configuration");
        assert!(!format!("{error:?} {error}").contains("sensitive"));
    }
    assert!(Config::parse(&"#".repeat(256 * 1024 + 1)).is_err());
    assert!(Config::parse(&config("secret_env = 'bad=name'")).is_err());
}

#[test]
fn endpoint_options_reject_credentialed_ambiguous_or_non_http_urls() {
    for url in [
        "ftp://panel.example.com",
        "https://user:password@panel.example.com",
        "https://panel.example.com?secret_key=secret",
        "https://panel.example.com/#fragment",
        "not a URL",
    ] {
        let options = Options::new(url, ServerId::new(1).unwrap(), Secret::new("secret"));
        let error = options.validate().unwrap_err();
        assert!(!format!("{error:?} {error}").contains("password"));
    }
    assert!(ServerId::new(0).is_err());
}

#[test]
fn cli_capabilities_and_version_do_not_claim_proxy_support() {
    let output = Command::new(env!("CARGO_BIN_EXE_terraris"))
        .arg("capabilities")
        .output()
        .unwrap();
    assert!(output.status.success());
    let body = String::from_utf8(output.stdout).unwrap();
    assert!(body.contains("proxy protocols: none"));
    assert!(body.contains("ppanel"));
    let output = Command::new(env!("CARGO_BIN_EXE_terraris"))
        .arg("version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn schema_copy_matches_recorded_digest() {
    use sha2::{Digest, Sha256};
    let digest = format!(
        "{:x}",
        Sha256::digest(include_bytes!("../proto/ppanel/server.proto"))
    );
    assert!(include_str!("../proto/ppanel/README.md").contains(&digest));
}
