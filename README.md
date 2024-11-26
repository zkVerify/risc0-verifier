# risc0-verifier

A `no-std` verifier for [RISC-Zero](https://github.com/risc0/risc0) STARK proofs.

This crate provides a way for deserializing

- `Proof` (aka risc0 receipt)
- the verification key `Vk` (aka risc0 image id)
- public inputs `Journal` (aka risc0 journal):

```rust
    use risc0_verifier::*;
    use std::path::PathBuf;
    use serde::Deserialize;
    use std::fs::File;

    #[derive(Deserialize)]
    pub struct Case {
        pub receipt_path: PathBuf,
        pub journal: Journal,
        pub vk: Vk,
    }

    let Case { receipt_path, journal, vk } =
        serde_json::from_reader(
            std::fs::File::open("./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json").unwrap()
        ).unwrap();

    let proof = ciborium::from_reader(File::open(receipt_path).unwrap()).unwrap();

    assert!(verify(vk, proof, journal).is_ok());
```

## Save a risc0 receipt

`risc0-verifier` accepts _any_ **serde** serialized risc0 `Receipt` that doesn't
contain groth16 proof. So, is you have a risc0's `Receipt` you can just serialize it
with `serde` in your preferred format (i.e. `ciborium` or `json`) and the deserialize
it to use with `risc0-verifier`. You can do the same thing with the `Journal` because the
serialized risc0's `Journal` can be deserialized for `risc0-verifier` as well. For the
`Vk` the risc0 image key bytes can be used directly to build it:

```rust
    use risc0_verifier::Vk;
    let vk : Vk = hex_literal::hex!("9db9988d9fbcacadf2bd29fc7c60b98bc4234342fe536eb983169eb6cc248009").into();
    let r0 : risc0_zkp::core::digest::Digest = [
        2375596445,
        2913778847,
        4230594034,
        2344181884,
        1111696324,
        3111015422,
        3063813763,
        159392972
    ].into();

    assert_eq!(vk.as_words(), r0.as_words());
    assert_eq!(vk.as_bytes(), r0.as_bytes());
```

## Verify a proof generate with an old risc0 version

If you need to verify a proof generated with an old risc0 prover version, for instance the `1.1.3`,
you can use [`verify_with_context`] instead:

```rust
    use risc0_verifier::*;
    use std::path::PathBuf;
    use serde::Deserialize;
    use std::fs::File;

    #[derive(Deserialize)]
    pub struct Case {
        pub receipt_path: PathBuf,
        pub journal: Journal,
        pub vk: Vk,
    }

    let Case { receipt_path, journal, vk } =
        serde_json::from_reader(
            std::fs::File::open("./resources/cases/prover_1.1.3/vm_1.1.3/poseidon2_22.json").unwrap()
        ).unwrap();

    let proof = ciborium::from_reader(File::open(receipt_path).unwrap()).unwrap();

    assert!(verify_with_context(&VerifierContext::v1_1(), vk, proof, journal).is_ok());
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

## Generate the proofs

In `generate_proofs` you can find a both a simple risc0 method and a program that
generate several proofs (different configurations) for a given compiled methods. You
can find some notes about how to generate sample proofs in the file `generate_proofs/notes.md`

## License

These crates are released under the [APACHE 2.0 license](LICENSE-APACHE2)
