//! Integration tests for vusi CLI

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_analyze_nonce_reuse_from_file() {
    Command::cargo_bin("vusi")
        .unwrap()
        .arg("analyze")
        .arg("tests/fixtures/nonce_reuse.json")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("nonce-reuse"))
        .stdout(predicate::str::contains(
            "62958994860637178871299877498639209302063112480839791435318431648713002718353",
        ));
}

#[test]
fn test_analyze_nonce_reuse_from_stdin() {
    let input = include_str!("fixtures/nonce_reuse.json");
    Command::cargo_bin("vusi")
        .unwrap()
        .arg("analyze")
        .arg("-")
        .write_stdin(input)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("nonce-reuse"));
}

#[test]
fn test_no_vulnerabilities_clean_exit() {
    let input = r#"[
      {"r": "123", "s": "456", "z": "789"},
      {"r": "999", "s": "888", "z": "777"}
    ]"#;
    Command::cargo_bin("vusi")
        .unwrap()
        .arg("analyze")
        .arg("-")
        .write_stdin(input)
        .assert()
        .code(0);
}

#[test]
fn test_json_output_schema() {
    let output = Command::cargo_bin("vusi")
        .unwrap()
        .arg("--json")
        .arg("analyze")
        .arg("tests/fixtures/nonce_reuse.json")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Output should be valid JSON");

    assert!(json["vulnerabilities"].is_array());
    let vuln = &json["vulnerabilities"][0];
    assert_eq!(vuln["type"].as_str(), Some("nonce-reuse"));
    assert!(vuln["confidence"].is_f64());
    assert!(vuln["signatures_count"].is_u64());
    assert!(vuln["recovered_key"]["private_key_decimal"].is_string());
    assert!(vuln["recovered_key"]["private_key_hex"].is_string());
    assert!(json["summary"]["vulnerabilities_found"].is_u64());

    let hex = vuln["recovered_key"]["private_key_hex"].as_str().unwrap();
    assert_eq!(hex.len(), 64, "private_key_hex should be 64 hex chars");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "should be valid hex"
    );
}

#[test]
fn test_invalid_input_error_exit() {
    Command::cargo_bin("vusi")
        .unwrap()
        .arg("analyze")
        .arg("-")
        .write_stdin("not valid json")
        .assert()
        .code(2);
}

#[test]
fn test_generate_and_analyze_related_nonce() {
    let mut cmd = Command::cargo_bin("vusi").unwrap();
    cmd.arg("generate")
        .arg("--weakness").arg("related")
        .arg("--count").arg("2")
        .arg("--seed").arg("12345");

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let mut analyze_cmd = Command::cargo_bin("vusi").unwrap();
    analyze_cmd.arg("analyze").arg("-");
    analyze_cmd.write_stdin(stdout);

    analyze_cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("related-nonce"))
        .stdout(predicate::str::contains("recovered"));
}

#[test]
fn test_generate_and_analyze_half_half() {
    let mut cmd = Command::cargo_bin("vusi").unwrap();
    cmd.arg("generate")
        .arg("--weakness").arg("half-half")
        .arg("--count").arg("1")
        .arg("--seed").arg("12345");

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let mut analyze_cmd = Command::cargo_bin("vusi").unwrap();
    analyze_cmd.arg("analyze").arg("-");
    analyze_cmd.write_stdin(stdout);

    analyze_cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("half-half"))
        .stdout(predicate::str::contains("recovered"));
}

#[test]
fn test_generate_and_analyze_lcg() {
    let mut cmd = Command::cargo_bin("vusi").unwrap();
    cmd.arg("generate")
        .arg("--weakness").arg("lcg")
        .arg("--count").arg("2")
        .arg("--seed").arg("12345");

    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let mut analyze_cmd = Command::cargo_bin("vusi").unwrap();
    analyze_cmd.arg("analyze").arg("-");
    analyze_cmd.write_stdin(stdout);

    analyze_cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("lcg"))
        .stdout(predicate::str::contains("recovered"));
}
