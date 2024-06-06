# risc0-verifier

A verifier for [RISC-Zero](https://github.com/risc0/risc0) STARK proofs.

This crate provides a way for deserializing the proof and the verification key (aka image id) and a function to check if the proof is correct:

```rust
    use risc0_verifier::{verify};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Data {
        vk: [u32; 8],
        proof: String,
        pubs: String,
    }

    let Data { vk, proof, pubs } =
        serde_json::from_reader(std::fs::File::open("./resources/valid_proof_1.json").unwrap()).unwrap();

    let proof = <Vec<u8>>::try_from(hex::decode(proof).unwrap()).unwrap();
    let pubs = <Vec<u8>>::try_from(hex::decode(pubs).unwrap()).unwrap();

    assert!(verify(vk.into(), &proof, &pubs).is_ok());
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
