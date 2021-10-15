#ifndef COSE_LIB_H
#define COSE_LIB_H

#include <cbor.h>

// Debugging functions
void printCBORToJSON(FILE *f, CborValue *value);
void printBufferToHex(FILE *f, uint8_t *buf, size_t count);

#endif