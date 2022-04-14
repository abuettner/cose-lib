/******************************************************************************
* MIT License
* 
* Copyright (c) 2021 Andre Büttner
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
******************************************************************************/

#include "cose-sign.h"
#include "cose.h"
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
    // @TODO: must be cbor encoded
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
        // @TODO: must be cbor encoded
        return uECC_verify(publicKey, sig_struct, sig_struct_size, coseMessage->signature, curve);
    }
    return 0;
}