#ifndef COSE_H
#define COSE_H

#include <cbor.h>

enum COSE_HEADER_TAG
{
    COSE_HEADER_ALG = 1,
    COSE_HEADER_CRIT = 2,
    COSE_HEADER_CONTENT_TYPE = 3,
    COSE_HEADER_KID = 4,
    COSE_HEADER_IV = 5,
    COSE_HEADER_PARTIAL_IV = 6,
    COSE_HEADER_COUNTER_SIGNATURE = 7
};

typedef struct
{
    int alg;
    char *contentType;
    uint8_t kid[64];
    size_t kidSize;
    uint8_t iv[64];
    size_t ivSize;

} COSE_HEADER;

typedef struct
{
    CborTag type;
    COSE_HEADER protectedHeader;
    COSE_HEADER unprotectedHeader;
    uint8_t payload[128];
    size_t payloadSize;
    uint8_t signature[64];
} COSE_Message;

void cose_init_header(COSE_HEADER *);
int cose_encode_header(COSE_HEADER, CborEncoder *);
int cose_decode_header(CborValue *, COSE_HEADER *);
size_t cose_encode_message(COSE_Message, uint8_t *, int);
int cose_decode_protected_header(uint8_t *, size_t, COSE_HEADER *);
int cose_decode_message(uint8_t *, size_t, COSE_Message *);

#endif