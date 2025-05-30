use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_babybear::POSEIDON2_BABYBEAR_24_PARAMS;
use zkhash::fields::babybear::FpBabyBear;
use zkhash::ark_ff::PrimeField; // for `.into_bigint()`
use std::slice;


#[no_mangle]
pub extern "C" fn poseidon2_permute_babybear24(input_ptr: *const u32,  output_ptr: *mut u32) {
    const T: usize = 24; // ← hardcoded size
    let poseidon2 = Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS);

    unsafe {
        let input_slice = std::slice::from_raw_parts(input_ptr, T );
        let output_slice = std::slice::from_raw_parts_mut(output_ptr, T);

        // Convert input u32 -> FpBabyBear
        let input_field_elements: Vec<FpBabyBear> = input_slice
            .iter()
            .map(|&x| FpBabyBear::from(x as u64))
            .collect();

        // Permute
        let output_field_elements = poseidon2.permutation(&input_field_elements);

        // Convert back FpBabyBear -> u32
        for (out, elem) in output_slice.iter_mut().zip(output_field_elements.iter()) {
            *out = elem.into_bigint().0[0] as u32;
        }
    }
}
