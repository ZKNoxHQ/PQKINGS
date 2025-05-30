#ifndef POSEIDON2_WRAPPER_H
#define POSEIDON2_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

// Function to permute input_size elements using Poseidon2 for BabyBear
void poseidon2_permute_babybear24(const uint32_t* input_ptr,  uint32_t* output_ptr);

#ifdef __cplusplus
}
#endif

#endif // POSEIDON2_WRAPPER_H
