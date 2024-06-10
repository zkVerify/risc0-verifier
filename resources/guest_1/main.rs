use risc0_zkvm::guest::env;

fn main() {
    // TODO: Implement your guest code here

    // read the input
    let input: u32 = env::read();

    let output = input;

    // write public output to the journal
    env::commit(&output);
}
