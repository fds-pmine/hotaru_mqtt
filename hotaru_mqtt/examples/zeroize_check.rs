// SAFETY_PROOF v5 M4.9 evidence harness.
//
// Goal: confirm that releasing a `Zeroizing<Vec<u8>>` at end-of-scope
// actually emits a wipe in `--release` (LLVM doesn't dead-store-eliminate
// the zeroing because the buffer is "about to be freed").
//
// Usage:
//   cargo asm --release --example zeroize_check zeroize_drop_check
//
// Look for a `memset`-style wipe (zero-fill of the heap allocation)
// emitted BEFORE the `__rust_dealloc` call. If the wipe is missing,
// LLVM elided it and the Zeroize guarantee is broken on this target.

use std::hint::black_box;
use zeroize::Zeroizing;

#[inline(never)]
#[unsafe(no_mangle)]
pub fn zeroize_drop_check(input: &[u8]) {
    let z: Zeroizing<Vec<u8>> = Zeroizing::new(input.to_vec());
    black_box(&z);
    // Implicit drop at end of scope — this is the line we're inspecting.
}

fn main() {
    let secret = [0xAAu8; 32];
    zeroize_drop_check(black_box(&secret));
}
