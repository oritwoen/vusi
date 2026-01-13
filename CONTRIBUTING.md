# Contributing

Contributions welcome! This includes code, bug fixes, new attack implementations, and test vectors.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch (`git checkout -b feature/my-change`)

## Development

```bash
just build
just test
just clippy
cargo fmt
```

## Pull Requests

1. Push to your fork
2. Open a PR against `main`
3. CI will run tests, formatting, and linting checks

## Adding New Attacks

1. Create new file in `src/attack/`
2. Implement `trait Attack` from `src/attack/mod.rs`
3. Add tests with real test vectors where possible
4. Export in `src/attack/mod.rs`

## Questions?

Open an issue if something is unclear.
