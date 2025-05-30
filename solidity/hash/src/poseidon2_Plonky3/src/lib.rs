


use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32}; // Import PrimeCharacteristicRing
use p3_symmetric::Permutation; // Import Permutation (corrected path)
use rand_xoshiro::Xoroshiro128Plus;
use rand::SeedableRng;
use std::mem;
use std::slice;
const WIDTH: usize = 24;
const OUTPUT_SIZE: usize = 24;

#[no_mangle]
pub extern "C" fn poseidon2_permute_babybear24(
    input_ptr: *const u32,
    output_ptr: *mut u32,
) {
    assert!(!input_ptr.is_null());
    assert!(!output_ptr.is_null());


    // Convert the C input array to a Rust array of BabyBear elements.
    let input_slice: &[u32] = unsafe { slice::from_raw_parts(input_ptr, WIDTH) };
    let mut input_baby_bear: [BabyBear; WIDTH] = [BabyBear::ZERO; WIDTH];
    for i in 0..WIDTH {
        input_baby_bear[i] = BabyBear::new(input_slice[i]); // Use BabyBear::new(u32)
    }

    // Create a Poseidon2 instance.
    let mut rng = Xoroshiro128Plus::seed_from_u64(1);
    let perm = Poseidon2BabyBear::<WIDTH>::new_from_rng_128(&mut rng);

    perm.permute_mut(&mut input_baby_bear);

    // Convert the resulting BabyBear elements back to a Rust slice of u32
    // and copy them to the C output pointer. We'll take the first OUTPUT_SIZE
    // elements of the Poseidon2 output.
    let output_slice: &mut [u32] = unsafe { slice::from_raw_parts_mut(output_ptr, OUTPUT_SIZE) };
    for i in 0..OUTPUT_SIZE {
        output_slice[i] = input_baby_bear[i].as_canonical_u32();
    }
}