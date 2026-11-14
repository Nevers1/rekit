fn main() {
    // Unicorn's bundled QEMU core uses 128-bit atomics, which GCC lowers to
    // libatomic calls. Without this the final link fails with an undefined
    // reference to `__atomic_compare_exchange_16`. The flag has to come after
    // the object files, hence `link-arg` rather than `link-lib`.
    println!("cargo:rustc-link-arg=-latomic");
}
