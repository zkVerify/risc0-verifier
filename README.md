# risc0-verifier

A verifier for [RISC-Zero](https://github.com/risc0/risc0) STARK proofs. This crate

This crate provides a way for deserializing the proof and the verification key (aka image id) and a function to check if the proof is correct:

```rust
    use risc0_verifier::{verify, ProofRawData};

    let (proof_raw_data, image_id_data): (ProofRawData, [u32; 8]) = load_data(&path);

    assert!(verify(proof_raw_data, image_id_data.into()).is_ok());
```

## Develop

This project uses [`cargo-make`](https://github.com/sagiegurari/cargo-make) to define
tasks and checks. Install this tool simply by `cargo install cargo-make` and run

```sh
cargo make ci
```

to run all CI's steps. You can also use `makers ci` and bypass `cargo` wrapper.

Another useful defined task is `coverage` that executes tests and compute code
coverage file `lcov.info`.

## License

These crates are released under the [APACHE 2.0 license](LICENSE-APACHE2)
