# vusi

[![Crates.io](https://img.shields.io/crates/v/vusi.svg)](https://crates.io/crates/vusi)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

ECDSA signature vulnerability analysis library and CLI tool.

## Features

- **Nonce Reuse Detection**: Identifies signatures using the same nonce (k value)
- **Private Key Recovery**: Recovers private keys from vulnerable signatures
- **Multiple Input Formats**: Supports JSON and CSV input
- **Flexible Output**: Human-readable or JSON output formats

## Installation

```bash
cargo install --path .
```

## Usage

### Analyze signatures from file

```bash
vusi analyze signatures.json
```

### Analyze from stdin

```bash
echo '[{"r":"...","s":"...","z":"..."}]' | vusi analyze
```

### JSON output

```bash
vusi --json analyze signatures.json
```

## Input Format

### JSON

```json
[
  {
    "r": "6819641642398093696120236467967538361543858578256722584730163952555838220871",
    "s": "5111069398017465712735164463809304352000044522184731945150717785434666956473",
    "z": "4834837306435966184874350434501389872155834069808640791394730023708942795899",
    "pubkey": null
  }
]
```

### CSV

```csv
r,s,z,pubkey
6819641642398093696120236467967538361543858578256722584730163952555838220871,5111069398017465712735164463809304352000044522184731945150717785434666956473,4834837306435966184874350434501389872155834069808640791394730023708942795899,
```

## Exit Codes

- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected
- `2`: Error (invalid input, etc.)

## Library Usage

```rust
use vusi::attack::{Attack, NonceReuseAttack};
use vusi::provider::load_signatures;

let signatures = load_signatures("signatures.json")?;
let attack = NonceReuseAttack;
let vulnerabilities = attack.detect(&signatures);

for vuln in vulnerabilities {
    if let Some(key) = attack.recover(&vuln) {
        println!("Recovered key: {}", key.private_key_decimal);
    }
}
```

## Development

### Run tests

```bash
cargo test
```

### Build release

```bash
cargo build --release
```

## License

MIT
