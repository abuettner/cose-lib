#include "uECC.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char priv[] = "00ca8f15463ced57446916376e7f32ea82e952664797cf52259ecfd3eccb9c32";
char pub[] = "ef54c31f041e8cd4e7a6a72e49ebb1f58bbb6001ea508d3df03a7eb943b86385753a6c48a536e71e6fdd5443968d3edfcbdf152acabe718ca4c439192f8e10df";
char sig[] = "A0CC5254B415668A7CFE1FFCD671A72EB463656EC8060CE702459BA2BDCBD260FE086A1B54B8761DD66C1180AC94A00427451173E45F47079462F1B4FA1EBA5C";
char hash[] = "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0";

void dump(const char* tag, uint8_t *vli, unsigned int size) {
  printf("%s: ", tag);
  for(unsigned i=0; i<size; ++i) {
      printf("%02X ", (unsigned)vli[i]);
  }
  printf("\n");
}

void strtobytes(const char* str, uint8_t* bytes, int count) {
  for (int c = 0; c < count; ++c) {
    if (sscanf(str, "%2hhx", &bytes[c]) != 1) {
      printf("Failed to read string to bytes");
      exit(1);
    }
    str += 2;
  }
}

int main() {
  int r;
  const struct uECC_Curve_t * curve = uECC_secp256r1();

  uint8_t private[32];
  uint8_t public[64];
  uint8_t signature[64];
  uint8_t hash_bin[32];

  uint8_t public2[64];

  strtobytes(priv, private, 32);
  strtobytes(pub, public, 64);
  strtobytes(sig, signature, 64);
  strtobytes(hash, hash_bin, 32);

  dump("private", private, sizeof(private));
  dump("public", public, sizeof(public));
  dump("signature", signature, sizeof(signature));
  dump("hash_bin", hash_bin, sizeof(hash_bin));

  uECC_compute_public_key(private, public2, curve);
  if (memcmp(public, public2, sizeof(public)) != 0) {
    printf("Public key doesn't match\n");
    return 1;
  }

  r = uECC_verify(public, hash_bin, sizeof(hash_bin), signature, curve);
  printf("verify result = %d\n", r);

  return 0;
}