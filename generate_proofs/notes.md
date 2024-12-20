# Notes

## Compile method

In order to have a stable image id we need to use the `cargo-risczero` command that compile
the method in the manifest path into docker image. This will generate both the elf and method-id
string for the risc0 vm version that the `Cargo.toml/Cargo.lock` indicate.

```sh
cargo risczero build --manifest-path methods/guest/Cargo.toml
```

Expected Output is something like follow

```text
 => => copying files 97.59MB                                                                                                                                                  0.1s
ELFs ready at:
ImageID: 90ef9a7e6df4e68df51665c69eb497339fd6b1f1f9698846ec4922bea777c422 - "target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/method/method"
```

Now the program to generate the proofs expecting to have a folder in the form of `method-<vm-version>`: for instance if
we used the version `1.2.0` we should run the follow commands:

```sh
mdamico@miklap:~/devel/first_r0$ mkdir host/method-1.2.0
mdamico@miklap:~/devel/first_r0$ echo "90ef9a7e6df4e68df51665c69eb497339fd6b1f1f9698846ec4922bea777c422" > host/method-1.2.0/info.txt
mdamico@miklap:~/devel/first_r0$ cp target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/method/method host/method-1.2.0/
```

## Change Prover version

We would fix the prover version for instance to `1.1.3` then in `host` folder we need to.

Edit `Cargo.toml` and set the following dependency line:

```toml
risc0-zkvm = { version = "=1.1.3", features = ["prove"] }
risc0-zkp = { version = "=1.1.3" }
```

This should be enough in most of the case but maybe in the next version the list can increase
due some new incompatibility (risc0 doesn't respect the semantic versioning :cry:). A workaround 
can be use the  follow script

```sh
export NEW_VERSION="1.1.3";

for p in risc0-zkvm risc0-circuit-recursion \
    risc0-circuit-recursion-sys risc0-circuit-rv32im risc0-circuit-rv32im-sys \
    risc0-groth16 risc0-binfmt risc0-zkp risc0-zkvm-platform \
    risc0-core risc0-sys risc0-build-kernel ;
do
    echo "----> $p to ${NEW_VERSION}";
    cargo update --precise "${NEW_VERSION}" "$p" ; 
done
```

It could be possible that this list is not updated. In this case try to run the
following script till you have no error.

```sh
for p in `cargo tree | grep -o -E "risc0-[^ ]+" | sort | uniq` ; 
do 
    echo "----> $p to ${NEW_VERSION}";
    cargo update --precise "${NEW_VERSION}" "$p" ; 
done
```

... If you stuck with something like follows:

```sh
mdamico@miklap:~/devel/first_r0$ cargo update --precise 1.0.3 risc0-groth16
    Updating crates.io index
error: failed to select a version for the requirement `risc0-groth16 = "^1.1.0-rc.1"`
candidate versions found which didn't match: 1.0.3
location searched: crates.io index
required by package `bonsai-sdk v0.9.1`
    ... which satisfies dependency `bonsai-sdk = "^0.9.0"` (locked to 0.9.1) of package `risc0-zkvm v1.0.3`
    ... which satisfies dependency `risc0-zkvm = "=1.0.3"` (locked to 1.0.3) of package `host v0.1.0 (/home/mdamico/devel/first_r0/host)`
```

Try also follow:

```sh
cargo update --precise 0.9.0 bonsai-sdk
```

## Change VM version

In `methods/guest` folder change the dependency in `Cargo.toml`

```toml
risc0-zkvm = { version = "=1.1.3", default-features = false, features = ['std'] }
risc0-zkp = { version = "=1.1.3" }
```

Also, here this cannot be enough and then like in the previous section run the following script:

```sh
export NEW_VERSION="=1.1.3";

for p in risc0-zkvm risc0-circuit-recursion \
    risc0-circuit-rv32im \
    risc0-groth16 risc0-binfmt risc0-zkp risc0-zkvm-platform \
    risc0-core ;
do
    echo "----> $p to ${NEW_VERSION}";
    cargo update --precise "${NEW_VERSION}" "$p" ; 
done
```
