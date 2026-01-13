# VUSI - ECDSA Signature Vulnerability Analysis

**Generated:** 2026-01-13
**Commit:** 1657ff6
**Branch:** main

## OVERVIEW

Rust library + CLI for detecting ECDSA nonce reuse vulnerabilities and recovering private keys. Part of btcsec ecosystem (alongside boha, vuke, shaha).

## STRUCTURE

```
vusi/
├── src/
│   ├── lib.rs           # Public API exports
│   ├── main.rs          # CLI (clap) - analyze subcommand
│   ├── signature.rs     # SignatureInput (IO) → Signature (domain), grouping
│   ├── math.rs          # Decimal ↔ Scalar, key recovery formulas
│   ├── provider.rs      # JSON/CSV parsing, auto-detection
│   └── attack/
│       ├── mod.rs       # trait Attack
│       └── nonce_reuse.rs
├── tests/
│   ├── integration.rs   # E2E with assert_cmd
│   └── fixtures/        # Test vectors (real Bitcoin TX)
└── .github/workflows/   # CI, crates.io, AUR publish
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Add new attack type | `src/attack/` | Implement `trait Attack` |
| Change input format | `src/provider.rs` | `detect_format()`, `parse_*()` |
| Modify key recovery math | `src/math.rs` | `recover_nonce()`, `recover_private_key()` |
| Add CLI subcommand | `src/main.rs` | `enum Command` |
| Signature grouping | `src/signature.rs` | `group_by_r_and_pubkey()` |

## CODE MAP

| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `Attack` | trait | attack/mod.rs:9 | Extensibility point for attack types |
| `NonceReuseAttack` | struct | attack/nonce_reuse.rs | Only impl in MVP |
| `Signature` | struct | signature.rs:27 | Domain model (k256::Scalar) |
| `SignatureInput` | struct | signature.rs:18 | IO model (serde, decimal strings) |
| `parse_scalar_decimal_strict` | fn | math.rs:14 | Decimal → Scalar, strict validation |
| `recover_private_key` | fn | math.rs:81 | Core recovery: `(s*k - z) / r` |
| `load_signatures` | fn | provider.rs:14 | Entry point for input |

## CONVENTIONS

- **Two-layer architecture**: `SignatureInput` (IO/serde) → `Signature` (domain/Scalar)
- **Decimal strings**: All r/s/z values as decimal strings in JSON/CSV
- **Strict parsing**: No leading zeros, no values ≥ secp256k1 order n
- **Pubkey normalization**: Lowercase, strip `0x` prefix before grouping
- **Exit codes**: 0=clean, 1=vulns found, 2=error

## ANTI-PATTERNS

- **NEVER** suppress type errors (`as any` equivalent)
- **NEVER** use mod n reduction on input (strict canonical only)
- **NEVER** implement WIF output (not in scope)
- **NEVER** parse raw transactions (input must be pre-parsed r/s/z)

## UNIQUE STYLES

- Test vector uses real Bitcoin TX `89380c9fb072cbb5...`
- Recovered key verified mathematically (signature round-trip)
- `confidence` field: 1.0 if pubkey known, 0.8 if None

## COMMANDS

```bash
just test          # cargo test --all-features
just build         # cargo build --release
just clippy        # cargo clippy -- -D warnings
just changelog     # git cliff -o CHANGELOG.md
just release 0.2.0 # Version bump + tag + changelog
```

## NOTES

- `k256` requires `PrimeField` trait import for `Scalar::from_repr()`
- `CtOption` → `Option` via `Option::from()`
- boha integration is optional feature (`--features boha`)
