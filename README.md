# risc0-verifier

A verifier for [RISC-Zero](https://github.com/risc0/risc0) STARK proofs.

This crate provides a way for deserializing the proof and the verification key (aka image id) and a function to check if the proof is correct:

```rust
    use risc0_verifier::{verify, extract_pubs_from_full_proof};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Data {
        image_id: [u32; 8],
        full_proof: String,
    }

    let Data {
        image_id,
        full_proof,
    } = serde_json::from_reader(std::fs::File::open("./resources/valid_proof_1.json").unwrap()).unwrap();

    let full_proof = <Vec<u8>>::try_from(hex::decode(full_proof).unwrap()).unwrap();
    let pubs = extract_pubs_from_full_proof(&full_proof).unwrap();

    assert!(verify(image_id.into(), &full_proof, pubs).is_ok());
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
