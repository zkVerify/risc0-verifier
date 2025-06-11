# How to add a new Risc0 vm version support

Every time that Risc0 release a **minor** version the proofs generated with
the new version cannot be verified by a verifier compiled with another minor
version. This is due to risc0 project considers the circuit changes a **minor**
changes even if it breaks the retro compatibility.

So we need to include the new circuit every time that risc0 release a new
minor version. We describe here a simple process of how to do it in a quite
mechanical way.

The steps are:

1. Compile the code using last release.
2. Generate tests cases.
3. Include and implement the new tests case.
4. Implement the new test case using the circuit crates released by risc0:
  all tests should pass now.
5. Move all tests related to the last version to use the new version
6. Update benchmarks to use the new version: bonus step check if there isn't
  any regression.
7. Replace the circuit that relay on risc0 crates with a one that use the code
  on this project by copy all needed data from the mainstream sources.

For the rest of this tutorial we're considering that risc0 **2.1.0** has released,
and we should implement it.

## Compile the code using last release

This step is the one with more _uncertain_ because some interfaces or values that we
used can be changed or moved in some other place: in this case you'll need to go a
little in deep and try to understand what's changed and how to port this changes. Don't
be scared because that changes was never dramatic.

To change the dependencies, go in `Cargo.toml` and for each `risc0-*` crate change
the `version = "=1.1.0"` reference into `version = "=1.3.0"`. Check the project with

```sh
cargo make ci
```

If

- Everything pass : Hooray! You hit the soother case!
- Some compilation issue: try to understand what is changed and report the changes on our code
- Some tests fails: that's the cleaver case, maybe is changed something in the `risc0-zkvm`
  verification code

## Generate Test case

Now we have just the newer verifier that support **only the old versions**. Before to implement
the newer circuit and add the new `VerifierContext::v1_3` we need to write some test case that's
exposing these needs.

To do it we should move in the `generate_proofs` folder and

1. Create a new method that uses the new vm 1.3.0
2. Generate the proof with the proofs for this new method with the new prover 1.3.0
3. Create the test cases
4. _Optional_: Generate the proofs for the old vm methods with the new prover
5. _Optional_: Generate the proofs for the new vm method with the old provers

Points 4 and 5 are not strictly necessary in the first stage where we would implement the
new circuit, but it is better to complete them to have a complete matrix coverage.

### Create a `1.3.0` vm method

In `notes.md` you could find all useful information about how to create a specific
method and prover version.
Anyway, we'll report them briefly.

To make the following scripts coherently export the `NEW_VERSION` env variable:

```sh
export NEW_VERSION="1.3.0";
```

Go in `methods/guest` folder change the dependency in `Cargo.toml` file:

```toml
risc0-zkvm = { version = "=1.3.0", default-features = false, features = ['std'] }
risc0-zkp = { version = "=1.3.0" }
```

If we're building the method for the last release version the previous step is enough, but
otherwise you need also run the follow script:

```sh
for p in risc0-zkvm risc0-circuit-recursion \
    risc0-circuit-rv32im \
    risc0-groth16 risc0-binfmt risc0-zkp risc0-zkvm-platform \
    risc0-core ;
do
    echo "----> $p to ${NEW_VERSION}";
    cargo update --precise "${NEW_VERSION}" "$p" ; 
done
```

The previous step is only necessary if the version you're using is not the last one, otherwise
the changes in `Cargo.toml` are enough.

If you don't have `cargo-risczero` command please install it and take care of the version that should be the same of 
the version for which you want to create the method. Use the command `rzup` for installing risc0 toolchain: `rzup install`
install the latest.

Now to compile it from `generate_proofs` you can just do

```sh
cargo risczero build --manifest-path methods/guest/Cargo.toml
```

The expected output is something like follow:

```text
 => => copying files 97.59MB                                                                                                                                                  0.1s
ELFs ready at:
ImageID: 90ef9a7e6df4e68df51665c69eb497339fd6b1f1f9698846ec4922bea777c422 - "target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/method/method"
```

We save the data in `host/method-1.3.0`:

```sh
mkdir host/method-${NEW_VERSION}
echo "90ef9a7e6df4e68df51665c69eb497339fd6b1f1f9698846ec4922bea777c422" > host/method-${NEW_VERSION}/info.txt
cp target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/method/method host/method-${NEW_VERSION}/
```

**Alert**: from version 2.0 the binary is moved in `target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/method.bin` file.

### Generate the proofs for 1.3.0 version

First, we should change the prover version: open `host/Cargo.toml` file set `version = "=1.3.0"` for each
risc0 crates (should be just `rsic0-zkvm` and `risc0-zkp`). Now **if we're pointing to the last risc0
version** this step is enough, otherwise you need also run the follow script in `host` folder:

```sh
for p in risc0-zkvm risc0-circuit-recursion \
    risc0-circuit-recursion-sys risc0-circuit-rv32im risc0-circuit-rv32im-sys \
    risc0-groth16 risc0-binfmt risc0-zkp risc0-zkvm-platform \
    risc0-core risc0-sys risc0-build-kernel ;
do
    echo "----> $p to ${NEW_VERSION}";
    cargo update --precise "${NEW_VERSION}" "$p" ; 
done
```

Now that we have the new method we should generate the proof. Open `host/src/main.rs` file and
change the line with the version lists to add the new version.

```rust
    let versions = ["1.2.0", "1.1.3", "1.1.1", "1.0.5", "1.0.1"];
```

into

```rust
    let versions = ["1.3.0", "1.2.0", "1.1.3", "1.1.1", "1.0.5", "1.0.1"];
```

Now you can run it to generate all the proofs in the `output` folder: first it will
create the proofs for `1.3.0` version that will be enough to write our first tests.

### Create the test cases

Now we have the proof, so we can build the test cases for the new zvm/prover/verifier.

In the folder `resources/cases` we can copy an old prover folder and change the name:

```sh
cp -r resources/cases/prover_1.2.0 resources/cases/prover_1.3.0
```

In every `json` file inside this folder replace string `resources/receipts/1.2.0-` with
`resources/receipts/1.3.0-` to point the correct folder where we'll put the proofs. The
others values should not change: the prover should not change the journal and the
verification key.

In that new folder we need to create a folder with the new cases related to the new vm:

```sh
cp -r resources/cases/prover_1.3.0/vm_1.2.0 resources/cases/prover_1.3.0/vm_1.3.0
```

In every json of this new folder `resources/cases/prover_1.3.0/vm_1.3.0` you need to
replace the string `resources/receipts/1.3.0-1.2.0` into `resources/receipts/1.3.0-1.3.0`:
the name stands for `<prover-version>-<vm-version>`.
Here also the vk is changed: you can get the new vk in `generate_proofs/host/output/1.3.0/id.json`
and replace the values in all json.

Now we should copy the proof in the `resource/receipts/1.3.0-*/` folders. Now we can make a
little digression here: The process to create all proof is fairly slow, but just have the
prover `1.3.0` against vm `1.3.0` proofs are enough to start: when we write the integration test
we'll see how to reduce the test scope in a first stage where we didn't have all tests.

So, when the proofs for the version `1.3.0` are ready we can copy them and then rename:

```sh
mkdir resources/receipts/1.3.0-1.3.0
cp generate_proofs/host/output/1.3.0/receipt_*.bin resources/receipts/1.3.0-1.3.0
cd resources/receipts/1.3.0-1.3.0
for f in `ls`; do mv $f ${f#receipt_}; done 
```

Now we can add the test cases to `tests/integration.rs`. Identify the module `v1_2` and
copy it into to `v1_3` to pay some attention on change the version references

```rust
mod v1_3 {
    use super::*;

    #[rstest]
    #[case::should_pass(VerifierContext::v1_3())]
    #[should_panic(expected = "control_id mismatch")]
    #[case::should_fails_with_old_verifier(VerifierContext::v1_0())]
    fn verify_valid_proof<SC: CircuitCoreDef, RC: CircuitCoreDef>(
        #[case] ctx: VerifierContext<SC, RC>,
        // #[files("./resources/cases/prover_1.3.*/**/*.json")] path: PathBuf, // Enable it only when you have all the proofs
        #[files("./resources/cases/prover_1.3.*/vm_1.3.0/*.json")] path: PathBuf, 
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        proof.verify(&ctx, case.vk, case.journal.digest()).unwrap()
    }
}

```

Add the new tests to the `segments`, `succinct` and `all` templates. We describe
only the succinct case, but the other are quite the same:

Add the follow case:

```rust
#[case::succinct_proof_v1_3(
    VerifierContext::v1_3(),
    "./resources/cases/prover_1.3.0/vm_1.3.0/succinct_22.json"
)]
```

Now we can run the tests, but it supposed that will not compile. In order to compile
it's enough to generate the new version context: we just replicate the previous `v1_2`
implementation. In `context.rs` add the following implementation for `VerifierContext`

```rust
impl VerifierContext<circuit::v1_2::CircuitImpl, circuit::v1_2::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext] for any risc0 proof generate for any `1.3.x` vm version.
    pub fn v1_3() -> Self {
        Self::empty(&circuit::v1_2::CIRCUIT, &circuit::v1_2::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_2())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_2())
    }
}
```

**We changed just the name of the function but not all other references**. This because we
want just to compile the tests and see that they're falling: we'll fix it later when we
implement the new circuit.

Now run again the tests that should compile butt all test related to verify the new prover
should fail: otherwise the new version doesn't introduce an incompatibility... **STRANGE**
double check it.

## Implement the new circuit by relay on risc0 crate

First add the following dependency in `Cargo.toml`:

```toml
risc0-circuit-recursion = { version = "=1.3.0", default-features = false }
```

and then edit `circuit.rs` to add the follow code:

```rust
pub mod v1_3 {
    pub use risc0_circuit_rv32im::*;
    use risc0_zkp::{core::digest::Digest, MAX_CYCLES_PO2, MIN_CYCLES_PO2};

    /// Fetch a control ID with the given hash, by name, and cycle limit as a power of two (po2) from
    /// the precomputed table. If the hash function is not precomputed, or the po2 is out of range,
    /// this function will return `None`.
    ///
    /// Supported values for hash_name are "sha-256", "poseidon2", and "blake2b".
    pub fn control_id(hash_name: &str, po2: usize) -> Option<Digest> {
        if !(MIN_CYCLES_PO2..=MAX_CYCLES_PO2).contains(&po2) {
            return None;
        }
        let idx = po2 - MIN_CYCLES_PO2;
        use control_id::*;
        match hash_name {
            "sha-256" => Some(SHA256_CONTROL_IDS[idx]),
            "poseidon2" => Some(POSEIDON2_CONTROL_IDS[idx]),
            "blake2b" => Some(BLAKE2B_CONTROL_IDS[idx]),
            _ => None,
        }
    }

    pub mod recursive {
        pub use risc0_circuit_recursion::*;
    }
}
```

Now we have the new circuit module to implements all stuff needed by `VerificationContext`.

In `segment.rs` add the follow method to `SegmentReceiptVerifierParameters` implementation:

```rust
/// v1.3 set of parameters used to verify a [SegmentReceipt].
pub fn v1_3() -> Self {
    use risc0_zkp::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
    Self::from_max_po2(
        &crate::circuit::v1_3::control_id,
        DEFAULT_MAX_PO2,
        PROOF_SYSTEM_INFO,
        crate::circuit::v1_3::CircuitImpl::CIRCUIT_INFO,
    )
}
```

In `succinct.rs` add the follow method to `SuccinctReceiptVerifierParameters` implementation:

```rust
/// v1_3 set of parameters used to verify a [SuccinctReceipt].
pub fn v1_3() -> Self {
    use crate::circuit::v1_3::recursive as circuit;
    Self {
        // ALLOWED_CONTROL_ROOT is a precalculated version of the control root, as calculated
        // by the allowed_control_root function above.
        control_root: circuit::control_id::ALLOWED_CONTROL_ROOT,
        inner_control_root: None,
        proof_system_info: PROOF_SYSTEM_INFO,
        circuit_info: circuit::CircuitImpl::CIRCUIT_INFO,
    }
}
```

And finally fix the verification context `v1_3()` implementation:

```rust
impl VerifierContext<circuit::v1_3::CircuitImpl, circuit::v1_3::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext] for any risc0 proof generate for any `1.3.x` vm version.
    pub fn v1_3() -> Self {
        Self::empty(&circuit::v1_3::CIRCUIT, &circuit::v1_3::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_3())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_3())
    }
}
```

Run the tests and cross the fingers... should pass now!!!

Just for completeness you should also add two tests cases at the end of `segment.rs`
and `succinct.rs` files:

```rust
    #[case::v1_3(SegmentReceiptVerifierParameters::v1_3().digest(), digest!("52a27aff2de5a8206e3e88cb8dcb087c1193ede8efaf4889117bc68e704cf29a"))]
```

```rust
    #[case::v1_3(SuccinctReceiptVerifierParameters::v1_3().digest(), digest!("21a829e931cda9f34723dc77d947efe264771fea83bc495b3903014d0fe50d57"))]
```

For the values you can put a fake and replace with the right value after. Anyway you
can do a double check later on main stream

- <https://github.com/risc0/risc0/blob/main/risc0/zkvm/src/receipt/segment.rs#L269>
- <https://github.com/risc0/risc0/blob/main/risc0/zkvm/src/receipt/succinct.rs#L362>

## Use this new version for all version independent tests

At the time we're writing these tests are all in `use_custom_local_implemented_hash_function`
but in general search in the file **all references to `v1_2()`** and check if it's a common test
or not, in other words is the claim is not depended on the version. If it's the case replace it with
`v1_3()` and fix the rest of the test accordantly.

## Update benchmarks to use the new version

Before do it run the benchmarks

```sh
cargo bench base
```

Then edit the file `bench/base.rs` and replace the references to the old context with
reference to the new context.

Now run the benchmarks again and check if there isn't any regression in the performance.

## Replace the circuits with local code

Now we are almost done and all our tests are in place and pass. Ok to be sure run the ci
yet another time:

```sh
cargo make ci
```

In this step we would replace the circuit implementations that we get from risc0 crates
with a local one.

To do it we use an incremental approach by create firs a `v1_3_1` module and just rename it
when all is done and work.

```sh
cp -r src/circuit/v1_2 src/circuit/v1_3_1
cp src/circuit/v1_2.rs src/circuit/v1_3_1.rs 
```

In `circuit.rs` add

```rust
pub mod v1_3_1;
```

Now You can open `src/circuit/v1_3_1.rs` and take it side by side with the source of
`risc0_circuit_rv32im`, you can use the IDE help to go into it from the `v1_3` module.
In the first step you should replace the content of local modules with the main streams ones.

```rust
pub mod control_id;
mod poly_ext;
mod taps;
```

For the rest of the file till the `recursion` module, you can check is some values is
changed: it should not happen, and you should not be afraid to forget something because
we have the tests that will come on rescue us.

Now in the `recursive` module you should do the same thing that you did before but with the
`risc0_circuit_recursion` crate.

Now check if we have not introduced any regression by run `cargo make ci` and then modify `v1_3` module to use our new one instead:

```rust
pub use v1_3_1 as v1_3

// Comment out the old impl
// pub mod v1_3 {
// ...
// }
```

Now run the ci again:

```sh
cargo make ci
```

If everything is fine just remove the man in the middle:

```sh
mv src/circuit/v1_3_1 src/circuit/v1_3
mv src/circuit/v1_1_1.rs src/circuit/v1_3.rs
```

and in `circuit.rs` remove the commented code, the `pub use v1_3_1 as v1_3` line
and change `pub mod v1_3_1;` with just

```rust
pub mod v1_3;
```

Run the ci again and... you **should get an error** because `cargo udeps` complain
about the unused crate `risc0-circuit-recursion` that is not used in the code. Remove
it from `Cargo.toml` and run for the last time

```sh
cargo make ci
```

🎆🚀🎆🚀🎆🚀🎆🚀🎆🚀 **HOORAY** 🎆🚀🎆🚀🎆🚀🎆🚀🎆🚀

