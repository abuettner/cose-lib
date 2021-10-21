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

    CborEncoder protectedEncoder;
    cbor_encoder_init(&protectedEncoder, coseMessage->protectedHeaderRaw, sizeof(coseMessage->protectedHeaderRaw), 0);
    cose_encode_header(coseMessage->protectedHeader, &protectedEncoder);
    coseMessage->protectedHeaderRawSize = cbor_encoder_get_buffer_size(&protectedEncoder, coseMessage->protectedHeaderRaw);

    // * * * * * Unprotected * * * * * //
    cose_init_header(&coseMessage->unprotectedHeader);

    // * * * * * Payload * * * * * //
    memmove(coseMessage->payload, payload, payloadSize);
    coseMessage->payloadSize = payloadSize;

    // * * * * * Signature * * * * * //
    uint8_t sig_struct[10 + coseMessage->protectedHeaderRawSize + coseMessage->payloadSize];
    size_t sig_struct_size = cose_create_sig_struct(coseMessage->protectedHeaderRaw, coseMessage->protectedHeaderRawSize, coseMessage->payload, coseMessage->payloadSize, sig_struct);
    uECC_sign(privateKey, sig_struct, sig_struct_size, coseMessage->signature, curve);
}

int cose_sign1_verify(COSE_Message *coseMessage, const uint8_t *publicKey, uECC_Curve curve)
{
    if (coseMessage->type == CborCOSE_Sign1Tag)
    {
        // @TODO use different algorithms

        // Verify signature
        uint8_t sig_struct[10 + coseMessage->protectedHeaderRawSize + coseMessage->payloadSize];
        size_t sig_struct_size = cose_create_sig_struct(coseMessage->protectedHeaderRaw, coseMessage->protectedHeaderRawSize, coseMessage->payload, coseMessage->payloadSize, sig_struct);
        printf("\nIt works: sig struct\n");
        printBufferToHex(stdout, coseMessage->protectedHeaderRaw, coseMessage->protectedHeaderRawSize);
        return uECC_verify(publicKey, sig_struct, sig_struct_size, coseMessage->signature, curve);
    }
    printf("\nError\n");
    return 0;
}