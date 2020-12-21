# Rust x509 parser example

Encode trust chain text files to `JSON` or decode `PEM` certificates to trust chain text files

## Usage

```bash
cargo run [encode | decode] /path/to/file
```

## Examples

```bash
cargo run encode ~/chain.txt
cargo run decode ~/cert.pem
```

```bash
cargo run decode ~/cert.pem > ~/out-chain.txt
cargo run encode ~/out-chain.txt > cert.json
cat ~/cert.json
```
