//! Input providers for loading signatures from files

use crate::signature::{Signature, SignatureInput};
use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::Num;
use std::io::{self, Read};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Format {
    Json,
    Csv,
}

pub fn load_signatures(input: &str) -> Result<Vec<Signature>> {
    let content = if input == "-" {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(input)?
    };

    parse_signatures(&content)
}

pub fn parse_signatures(content: &str) -> Result<Vec<Signature>> {
    let content = content.strip_prefix(BOM).unwrap_or(content);
    let format = detect_format(content)?;
    let inputs = match format {
        Format::Json => parse_json(content)?,
        Format::Csv => parse_csv(content)?,
    };

    inputs
        .into_iter()
        .map(|input| {
            let normalized = normalize_input(input)?;
            Signature::try_from(normalized)
        })
        .collect()
}

fn normalize_value(s: &str) -> Result<String> {
    let trimmed = s.trim();
    if let Some(hex_str) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if hex_str.is_empty() {
            bail!("Empty hex value after 0x prefix");
        }
        if !hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("Invalid hex string: only hex digits allowed after 0x prefix");
        }
        let biguint = BigUint::from_str_radix(hex_str, 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse hex value: {}", e))?;
        Ok(biguint.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn normalize_input(mut input: SignatureInput) -> Result<SignatureInput> {
    input.r = normalize_value(&input.r)?;
    input.s = normalize_value(&input.s)?;
    input.z = normalize_value(&input.z)?;
    Ok(input)
}

const BOM: &str = "\u{FEFF}";

pub fn detect_format(content: &str) -> Result<Format> {
    let trimmed = content.strip_prefix(BOM).unwrap_or(content).trim_start();

    if trimmed.starts_with('[') {
        return Ok(Format::Json);
    }

    if let Some(first_line) = trimmed.lines().next() {
        let columns: Vec<String> = first_line
            .split(',')
            .map(|c| c.trim().to_lowercase())
            .collect();
        let has_r = columns.iter().any(|c| c == "r");
        let has_s = columns.iter().any(|c| c == "s");
        let has_z = columns.iter().any(|c| c == "z");
        if has_r && has_s && has_z {
            return Ok(Format::Csv);
        }
    }

    bail!("Unable to detect input format. Use JSON array or CSV with r,s,z header.")
}

fn parse_json(content: &str) -> Result<Vec<SignatureInput>> {
    Ok(serde_json::from_str(content)?)
}

fn parse_csv(content: &str) -> Result<Vec<SignatureInput>> {
    let mut reader = csv::Reader::from_reader(content.as_bytes());
    let mut inputs = Vec::new();
    for result in reader.deserialize() {
        inputs.push(result?);
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_signatures() {
        let json = r#"[{"r": "123", "s": "456", "z": "789"}]"#;
        let sigs = parse_signatures(json).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn test_parse_csv_signatures() {
        let csv = "r,s,z,pubkey\n123,456,789,";
        let sigs = parse_signatures(csv).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn test_auto_detect_json() {
        let json = r#"  [{"r": "1", "s": "2", "z": "3"}]"#;
        assert_eq!(detect_format(json).unwrap(), Format::Json);
    }

    #[test]
    fn test_auto_detect_csv() {
        let csv = "r,s,z\n1,2,3";
        assert_eq!(detect_format(csv).unwrap(), Format::Csv);
    }

    #[test]
    fn test_auto_detect_json_with_bom() {
        let json = "\u{FEFF}[{\"r\":\"1\",\"s\":\"2\",\"z\":\"3\"}]";
        assert_eq!(detect_format(json).unwrap(), Format::Json);
    }

    #[test]
    fn test_auto_detect_csv_with_bom() {
        let csv = "\u{FEFF}r,s,z\n1,2,3";
        assert_eq!(detect_format(csv).unwrap(), Format::Csv);
    }

    #[test]
    fn test_invalid_json_error() {
        let result = parse_signatures("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_value_decimal_passthrough() {
        let result = normalize_value("12345").unwrap();
        assert_eq!(result, "12345");
    }

    #[test]
    fn test_normalize_value_hex_to_decimal() {
        let result = normalize_value("0xff").unwrap();
        assert_eq!(result, "255");
    }

    #[test]
    fn test_normalize_value_hex_uppercase_prefix() {
        let result = normalize_value("0XFF").unwrap();
        assert_eq!(result, "255");
    }

    #[test]
    fn test_normalize_value_hex_large() {
        let result =
            normalize_value("0x0f13c7c741321a95510ba98792bc9050efdce2e422be4610f162449adce92a47")
                .unwrap();
        assert_eq!(
            result,
            "6819641642398093696120236467967538361543858578256722584730163952555838220871"
        );
    }

    #[test]
    fn test_normalize_value_trims_whitespace() {
        let result = normalize_value("  0xff  ").unwrap();
        assert_eq!(result, "255");
    }

    #[test]
    fn test_normalize_value_empty_hex_fails() {
        let result = normalize_value("0x");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_value_invalid_hex_chars_fails() {
        let result = normalize_value("0xGGGG");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_json_signatures() {
        let json = r#"[{
            "r": "0x0f13c7c741321a95510ba98792bc9050efdce2e422be4610f162449adce92a47",
            "s": "0x0b4cc3447a2793c4598e5829827f38c67f72e4c3d4688019cd94066b9e7df6b9",
            "z": "0x0ab06bc2befd52cde3b2de709a642e437b8a7187cc28de72bd5aff4a896e047b"
        }]"#;
        let sigs = parse_signatures(json).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn test_parse_hex_csv_signatures() {
        let csv = "r,s,z,pubkey\n0xff,0xfe,0xfd,";
        let sigs = parse_signatures(csv).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn test_parse_mixed_hex_decimal_signatures() {
        let json = r#"[{"r": "0xff", "s": "456", "z": "0xab"}]"#;
        let sigs = parse_signatures(json).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn test_parse_json_with_bom() {
        let json = "\u{FEFF}[{\"r\":\"123\",\"s\":\"456\",\"z\":\"789\"}]";
        let sigs = parse_signatures(json).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    #[test]
    fn test_parse_csv_with_bom() {
        let csv = "\u{FEFF}r,s,z,pubkey\n123,456,789,\n";
        let sigs = parse_signatures(csv).unwrap();
        assert_eq!(sigs.len(), 1);
    }
}
