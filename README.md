# risc0-verifier

A `no-std` verifier for [RISC-Zero](https://github.com/risc0/risc0) STARK proofs.

This crate provides a way for deserializing

- `Proof` (aka risc0 receipt)
- the verification key `Vk` (aka risc0 image id)
- public inputs `Journal` (aka risc0 journal)

And then you can verify the given proof generated with a specific risc0 vm version against
the verification key and public inputs.

In order to choose the vm version you should get the `VerifierContext` coherent with the
vm version used to generate the proof. For instance the following code assume that the proof
was generated with risc0 vm version `1.2`.

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

    // This just deserialize a risc0 receipt serialized with `ciborium` crate
    let proof = ciborium::from_reader(File::open(receipt_path).unwrap()).unwrap();

    assert!(verify(&VerifierContext::v1_2(), vk, proof, journal).is_ok());
```

## Save a risc0 receipt

`risc0-verifier` accepts _any_ **serde** serialized risc0 `Receipt` that doesn't
contain any groth16 proof. So, is you have a risc0's `Receipt` you can just serialize it
with `serde` in your preferred format (i.e. `ciborium` or `json`) and then deserialize
it into `risc0-verifier::Proof` like in the previous example to call `risc0-verifier::verify`.

You can also do the same thing with the `Journal` because the serialized risc0's `Journal` can
be deserialized into `risc0-verifier::Journal` as well. For the
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

## Convert Old ZkVerify risc0 proofs

Till the `0.2.0` version of this crate the proofs and public inputs accepted by zKVerify
was coded with `bincode` crate that unfortunately doesn't support `no-std` (old versions
of zkVerify used native code to implement risc0 verifier). Now zkVerify use this crate to
implement the risc0 verification in wasm and the binary format is changed:

- the proof are encoded by use CBOR that is less efficient (20% bigger) but there are
  `no-std` implementations
- The journal could be sent just by its binary payload in the field `bytes`

This crate also provide a simple command line tool to convert old proof format to the new
one. You can use both `cargo make build_convert` or

```sh
cargo build --bin convert_old --release --features convert
```

and the binary `./target/release/convert_old` can be used to convert both `Journal` and `Proof`:
the default behavior is to convert binary proofs from standard input to standard output.

```sh
convert_old --help
Usage: convert_old [-x] [-X] [-j] [-i <input>] [-o <output>]

Perform conversion.

Options:
  -x, --hex-input   hex input format
  -X, --hex-output  hex output format
  -j, --journal     convert journal
  -i, --input       input data (none for stdout)
  -o, --output      output data (none for stdout)
  --help, help      display usage information
```

## License

These crates are released under the [APACHE 2.0 license](LICENSE-APACHE2)
