# Filecoin Phase2

Library and binary to run phase2 of the Groth16 trusted-setups for Filecoin's circuits.

## Build Library

```
$ cargo build
```

## Build `phase2` Binary

```
$ cargo build --release --bins && cp target/release/filecoin-phase2 phase2
$ ./phase2 help
```

## Run Tests

```
$ cargo test
```

## License

MIT or Apache 2.0
