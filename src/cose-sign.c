#include "cose-sign.h"
#include "cose.h"
#include "cose-lib.h"
#include <cbor.h>
#include <stdio.h>

size_t cose_create_sig_struct(uint8_t *protectedBuf, size_t protectedBufSize, uint8_t *payload, size_t payloadSize, uint8_t *sig_struct_out)
{
    memmove(sig_struct_out, "Signature1", 10);
    memmove(sig_struct_out + 10, protectedBuf, protectedBufSize);
    memmove(sig_struct_out + 10 + protectedBufSize, payload, payloadSize);
    return 10 + protectedBufSize + payloadSize;
}

void cose_sign1_sign(uint8_t *payload, size_t payloadSize, const uint8_t *privateKey, uECC_Curve curve, COSE_Message *coseMessage)
{
    coseMessage->type = CborCOSE_Sign1Tag;
    // * * * * * Protected * * * * * //
    cose_init_header(&coseMessage->protectedHeader);
    // @TODO use different algorithms
    coseMessage->protectedHeader.alg = -8; // EdDSA
    memmove(coseMessage->protectedHeader.kid, "kid2", 4);
    coseMessage->protectedHeader.kidSize = 4;

    uint8_t protectedBuf[512];
    size_t protectedBufSize = cose_encode_protected_header(coseMessage->protectedHeader, protectedBuf);

    // * * * * * Unprotected * * * * * //
    cose_init_header(&coseMessage->unprotectedHeader);

    // * * * * * Payload * * * * * //
    coseMessage->payload = payload;
    coseMessage->payloadSize = payloadSize;

    // * * * * * Signature * * * * * //
    uint8_t sig_struct[10 + protectedBufSize + coseMessage->payloadSize];
    size_t sig_struct_size = cose_create_sig_struct(protectedBuf, protectedBufSize, coseMessage->payload, coseMessage->payloadSize, sig_struct);
    uECC_sign(privateKey, sig_struct, sig_struct_size, coseMessage->signature, curve);
}

int cose_sign1_verify(COSE_Message *coseMessage, const uint8_t *publicKey, uECC_Curve curve)
{
    if (coseMessage->type == CborCOSE_Sign1Tag)
    {

        // @TODO use different algorithms

        // Verify signature
        uint8_t protectedBuf[128];
        size_t protectedBufSize = cose_encode_protected_header(coseMessage->protectedHeader, protectedBuf);
        uint8_t sig_struct[10 + protectedBufSize + coseMessage->payloadSize];
        size_t sig_struct_size = cose_create_sig_struct(protectedBuf, protectedBufSize, coseMessage->payload, coseMessage->payloadSize, sig_struct);
        return uECC_verify(publicKey, sig_struct, sig_struct_size, coseMessage->signature, curve);
    }

    return 0;
}