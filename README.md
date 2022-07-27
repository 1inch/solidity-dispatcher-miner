# solidity-dispatcher-miner

### Usage

Use KECCAK256-based hash function `keccak256(selector, salt_of_5_bytes) % N`:

```bash
cargo run --release 8
```

Or use XOR-based hash function `rotale_left(selector ^ salt_lower_4_bytes, salt_top_byte) % 1000003 % N` (it is 100x times faster):

```bash
cargo run --release 8 --use-xor-hash
```