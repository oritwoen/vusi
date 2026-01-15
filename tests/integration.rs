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
#[cfg(feature = "polynonce")]
fn test_analyze_polynonce_from_file() {
    Command::cargo_bin("vusi")
        .unwrap()
        .arg("analyze")
        .arg("--attack=polynonce")
        .arg("tests/fixtures/polynonce.json")
        .assert()
        .code(1) // vulnerabilities found
        .stdout(predicate::str::contains("polynonce"))
        .stdout(predicate::str::contains("Private Key (decimal): 12345"));
}

#[test]
#[cfg(feature = "polynonce")]
fn test_polynonce_json_output_schema() {
    let output = Command::cargo_bin("vusi")
        .unwrap()
        .arg("--json")
        .arg("analyze")
        .arg("--attack=polynonce")
        .arg("tests/fixtures/polynonce.json")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Output should be valid JSON");

    assert!(json["vulnerabilities"].is_array());
    let vuln = &json["vulnerabilities"][0];
    assert_eq!(vuln["type"].as_str(), Some("polynonce"));
    assert!(vuln["confidence"].is_f64());
    assert!(vuln["signatures_count"].is_u64());
    assert!(vuln["recovered_key"]["private_key_decimal"].is_string());
    assert!(vuln["recovered_key"]["private_key_hex"].is_string());
    assert!(json["summary"]["vulnerabilities_found"].is_u64());

    // Verify correct key was recovered (d = 12345)
    assert_eq!(
        vuln["recovered_key"]["private_key_decimal"].as_str(),
        Some("12345"),
        "Should recover private key 12345"
    );

    let hex = vuln["recovered_key"]["private_key_hex"].as_str().unwrap();
    assert_eq!(hex.len(), 64, "private_key_hex should be 64 hex chars");
    assert!(
        hex.chars().all(|c| c.is_ascii_hexdigit()),
        "should be valid hex"
    );
    assert!(hex.ends_with("3039"), "hex should end with 3039 (12345 in hex)");
}
