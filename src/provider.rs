//! Input providers for loading signatures from files

use crate::signature::{Signature, SignatureInput};
use anyhow::{bail, Result};
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
    let format = detect_format(content)?;
    let inputs = match format {
        Format::Json => parse_json(content)?,
        Format::Csv => parse_csv(content)?,
    };

    inputs.into_iter().map(Signature::try_from).collect()
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
    fn test_invalid_json_error() {
        let result = parse_signatures("not json");
        assert!(result.is_err());
    }
}
