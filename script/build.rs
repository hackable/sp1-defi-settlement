use sp1_build::build_program_with_args;

fn main() {
    // Build zkVM guest program so its ELF can be embedded.
    build_program_with_args("../program", Default::default());
}
