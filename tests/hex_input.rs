//! Integration tests for hex-encoded input values

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_analyze_nonce_reuse_hex_from_file() {
    Command::cargo_bin("vusi")
        .unwrap()
        .arg("analyze")
        .arg("tests/fixtures/nonce_reuse_hex.json")
        .assert()
        .code(1)
        .stdout(predicate::str::contains("nonce-reuse"))
        .stdout(predicate::str::contains(
            "62958994860637178871299877498639209302063112480839791435318431648713002718353",
        ));
}

#[test]
fn test_hex_json_output_matches_decimal() {
    let hex_output = Command::cargo_bin("vusi")
        .unwrap()
        .arg("--json")
        .arg("analyze")
        .arg("tests/fixtures/nonce_reuse_hex.json")
        .output()
        .unwrap();

    let dec_output = Command::cargo_bin("vusi")
        .unwrap()
        .arg("--json")
        .arg("analyze")
        .arg("tests/fixtures/nonce_reuse.json")
        .output()
        .unwrap();

    assert_eq!(hex_output.status.code(), Some(1));
    assert_eq!(dec_output.status.code(), Some(1));

    let hex_json: serde_json::Value =
        serde_json::from_slice(&hex_output.stdout).expect("hex output should be valid JSON");
    let dec_json: serde_json::Value =
        serde_json::from_slice(&dec_output.stdout).expect("decimal output should be valid JSON");

    assert_eq!(
        hex_json["vulnerabilities"][0]["recovered_key"]["private_key_decimal"],
        dec_json["vulnerabilities"][0]["recovered_key"]["private_key_decimal"],
        "Hex and decimal inputs should recover the same private key"
    );
}

#[test]
fn test_hex_from_stdin() {
    let input = include_str!("fixtures/nonce_reuse_hex.json");
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
fn test_mixed_hex_decimal_input() {
    let input = r#"[
      {"r": "0x0f13c7c741321a95510ba98792bc9050efdce2e422be4610f162449adce92a47",
       "s": "5111069398017465712735164463809304352000044522184731945150717785434666956473",
       "z": "0x0ab06bc2befd52cde3b2de709a642e437b8a7187cc28de72bd5aff4a896e047b"},
      {"r": "6819641642398093696120236467967538361543858578256722584730163952555838220871",
       "s": "0x44d4f1763d0910413d9e95e70b3f6066eec7a19890152c1b0c9aaf1e8aefac7f",
       "z": "108808786585075507407446857551522706228868950080801424952567576192808212665067"}
    ]"#;
    Command::cargo_bin("vusi")
        .unwrap()
        .arg("analyze")
        .arg("-")
        .write_stdin(input)
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "62958994860637178871299877498639209302063112480839791435318431648713002718353",
        ));
}
