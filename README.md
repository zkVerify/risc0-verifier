# risc0-verifier

A verifier for [RISC-Zero](https://github.com/risc0/risc0) STARK proofs.

This crate provides a way for deserializing the proof and the verification key (aka image id) and a function to check if the proof is correct:

```rust
    use risc0_verifier::{verify};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Data {
        proof_raw_data: String,
        image_id: [u32; 8],
    }

    let Data {
        proof_raw_data,
        image_id,
    } = serde_json::from_reader(std::fs::File::open("./resources/valid_proof_1.json").unwrap())
        .unwrap();

    let proof_raw_data = <Vec<u8>>::try_from(hex::decode(proof_raw_data).unwrap()).unwrap();

    assert!(verify(&proof_raw_data, image_id.into()).is_ok());
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
