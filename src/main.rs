//! CLI for ECDSA signature vulnerability analysis

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::process::ExitCode;
use std::fmt::Write;
#[cfg(feature = "biased-nonce")]
use vusi::attack::biased_nonce::{BiasType, ReductionAlgorithm};
#[cfg(feature = "biased-nonce")]
use vusi::attack::BiasedNonceAttack;
#[cfg(feature = "polynonce")]
use vusi::attack::PolynonceAttack;
use vusi::attack::{Attack, NonceReuseAttack, Vulnerability};
use vusi::math::scalar_to_decimal_string;
use vusi::provider::load_signatures;
use vusi::signature::Signature;

#[derive(Parser)]
#[command(name = "vusi")]
#[command(about = "ECDSA signature vulnerability analysis")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    Analyze {
        #[arg(default_value = "-")]
        input: String,

        #[arg(
            long,
            default_value = "nonce-reuse",
            help = "Attack type: nonce-reuse, polynonce, biased-nonce"
        )]
        attack: String,

        #[arg(
            long,
            default_value = "1",
            help = "Polynomial degree for polynonce attack (1=linear, 2=quadratic)"
        )]
        degree: usize,

        #[arg(
            long,
            default_value = "lsb",
            help = "Bias type for biased-nonce attack: lsb, msb, range"
        )]
        bias_type: String,

        #[arg(
            long,
            default_value = "8",
            help = "Known bits for biased-nonce (range uses this as max nonce bits)"
        )]
        known_bits: usize,

        #[arg(
            long,
            default_value = "lll",
            help = "Lattice reduction: lll, windowed-lll"
        )]
        reduction: String,

        #[arg(
            long,
            default_value = "20",
            help = "Block size for windowed-lll reduction"
        )]
        window_block_size: usize,

        #[arg(long, default_value = "2", help = "Rounds for windowed-lll reduction")]
        window_rounds: usize,

        #[arg(long, help = "Max signatures to sample for biased-nonce recovery")]
        max_samples: Option<usize>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(found_vulnerabilities) => {
            if found_vulnerabilities {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Command::Analyze {
            input,
            attack,
            degree: _polynonce_degree,
            bias_type,
            known_bits,
            reduction,
            window_block_size,
            window_rounds,
            max_samples,
        } => {
            let signatures = load_signatures(&input)?;

            let (vulns, attack_impl): (Vec<Vulnerability>, Box<dyn Attack>) = match attack.as_str()
            {
                "nonce-reuse" => {
                    let attack = NonceReuseAttack;
                    let vulns = attack.detect(&signatures);
                    (vulns, Box::new(attack))
                }
                #[cfg(feature = "polynonce")]
                "polynonce" => {
                    let attack = PolynonceAttack::new(_polynonce_degree);
                    let vulns = attack.detect(&signatures);
                    (vulns, Box::new(attack))
                }
                #[cfg(feature = "biased-nonce")]
                "biased-nonce" => {
                    let bias_type = match bias_type.as_str() {
                        "lsb" => BiasType::Lsb,
                        "msb" => BiasType::Msb,
                        "range" => BiasType::Range,
                        _ => anyhow::bail!("Unknown bias type: {}", bias_type),
                    };
                    if bias_type != BiasType::Range && known_bits < 4 {
                        anyhow::bail!("Known bits must be >= 4 for biased-nonce");
                    }
                    if bias_type == BiasType::Range && (known_bits == 0 || known_bits > 256) {
                        anyhow::bail!("Range max bits must be between 1 and 256");
                    }
                    let reduction = match reduction.as_str() {
                        "lll" => ReductionAlgorithm::Lll,
                        "windowed-lll" => ReductionAlgorithm::WindowedLll {
                            block_size: window_block_size,
                            rounds: window_rounds,
                        },
                        _ => anyhow::bail!("Unknown reduction: {}", reduction),
                    };
                    let attack =
                        BiasedNonceAttack::new(bias_type, known_bits, reduction, max_samples);
                    let vulns = attack.detect(&signatures);
                    (vulns, Box::new(attack))
                }
                _ => anyhow::bail!("Unknown attack type: {}", attack),
            };

            let output = format_output(&vulns, attack_impl.as_ref(), &signatures, cli.json)?;
            println!("{}", output);

            Ok(!vulns.is_empty())
        }
    }
}

#[derive(Serialize)]
struct OutputReport {
    vulnerabilities: Vec<VulnerabilityOutput>,
    summary: SummaryOutput,
}

#[derive(Serialize)]
struct VulnerabilityOutput {
    #[serde(rename = "type")]
    vuln_type: String,
    confidence: f64,
    signatures_count: usize,
    pubkey: Option<String>,
    r_value: String,
    recovered_key: Option<RecoveredKeyOutput>,
    recovery_status: String,
    recovery_reason: Option<String>,
}

#[derive(Serialize)]
struct RecoveredKeyOutput {
    private_key_decimal: String,
    private_key_hex: String,
}

#[derive(Serialize)]
struct SummaryOutput {
    total_signatures: usize,
    vulnerabilities_found: usize,
    keys_recovered: usize,
}

fn format_output(
    vulns: &[Vulnerability],
    attack: &dyn Attack,
    sigs: &[Signature],
    json: bool,
) -> Result<String> {
    let mut vuln_outputs = Vec::new();
    let mut keys_recovered = 0;

    for vuln in vulns {
        let recovered = attack.recover(vuln);
        let (recovery_status, recovery_reason, recovered_key_output) = if let Some(key) = &recovered
        {
            keys_recovered += 1;
            (
                "recovered".to_string(),
                None,
                Some(RecoveredKeyOutput {
                    private_key_decimal: key.private_key_decimal.clone(),
                    private_key_hex: key.private_key_hex.clone(),
                }),
            )
        } else {
            (
                "unrecoverable".to_string(),
                Some("all pairs have s1 == s2".to_string()),
                None,
            )
        };

        vuln_outputs.push(VulnerabilityOutput {
            vuln_type: vuln.attack_type.clone(),
            confidence: vuln.group.confidence,
            signatures_count: vuln.group.signatures.len(),
            pubkey: vuln.group.pubkey.clone(),
            r_value: scalar_to_decimal_string(&vuln.group.r),
            recovered_key: recovered_key_output,
            recovery_status,
            recovery_reason,
        });
    }

    let report = OutputReport {
        vulnerabilities: vuln_outputs,
        summary: SummaryOutput {
            total_signatures: sigs.len(),
            vulnerabilities_found: vulns.len(),
            keys_recovered,
        },
    };

    if json {
        Ok(serde_json::to_string_pretty(&report)?)
    } else {
        let mut output = String::new();
        writeln!(output, "Analyzed {} signatures\n", sigs.len())?;

        if vulns.is_empty() {
            writeln!(output, "No vulnerabilities found.")?;
        } else {
            writeln!(output, "Found {} vulnerabilities:\n", vulns.len())?;

            for (i, vuln_output) in report.vulnerabilities.iter().enumerate() {
                writeln!(output, "Vulnerability #{}", i + 1)?;
                writeln!(output, "  Type: {}", vuln_output.vuln_type)?;
                writeln!(output, "  Confidence: {:.1}", vuln_output.confidence)?;
                writeln!(output, "  Signatures: {}", vuln_output.signatures_count)?;
                if let Some(pk) = &vuln_output.pubkey {
                    writeln!(output, "  Public Key: {}", pk)?;
                }
                writeln!(output, "  R Value: {}", vuln_output.r_value)?;

                if let Some(key) = &vuln_output.recovered_key {
                    writeln!(output, "  Status: {}", vuln_output.recovery_status)?;
                    writeln!(output, "  Private Key (decimal): {}", key.private_key_decimal)?;
                    writeln!(output, "  Private Key (hex): {}", key.private_key_hex)?;
                } else {
                    writeln!(output, "  Status: {}", vuln_output.recovery_status)?;
                    if let Some(reason) = &vuln_output.recovery_reason {
                        writeln!(output, "  Reason: {}", reason)?;
                    }
                }
                writeln!(output)?;
            }
        }

        Ok(output)
    }
}
