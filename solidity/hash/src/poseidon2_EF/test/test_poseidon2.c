#include <stdio.h>
#include <stdint.h>
#include <poseidon2_wrapper.h>

int main() {
    // Example input array (24 elements)
    uint32_t input[24] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};

    uint32_t input2[24]={886409618, 1327899896, 1902407911, 591953491, 648428576, 1844789031, 1198336108,
            355597330, 1799586834, 59617783, 790334801, 1968791836, 559272107, 31054313,
            1042221543, 474748436, 135686258, 263665994, 1962340735, 1741539604, 449439011,
            1131357108, 50869465, 1589724894};


    uint32_t output[24];

    // Call the Poseidon2 permutation function
    poseidon2_permute_babybear24(input,  output);

    // Print the output
    printf("Permuted Output:\n");
    for (int i = 0; i < 24; i++) {
        printf("%x ", output[i]);
    }
    printf("\n");

      // Call the Poseidon2 permutation function
      poseidon2_permute_babybear24(input2,  output);

      // Print the output
      printf("Permuted Output:\n");
      for (int i = 0; i < 24; i++) {
          printf("%d ", output[i]);
      }
      printf("\n");

    return 0;
}
