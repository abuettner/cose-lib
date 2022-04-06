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
#include <stdio.h>
#include <cbor.h>
#include <cborjson.h>

#include <cose.h>
#include <cose-sign.h>
#include <cose-lib.h>
#include <cose-go.h>

#include "uECC.h"
#include <openssl/sha.h>

int main()
{

    // Generate key pair
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uint8_t private1[32];
    uint8_t public1[64];
    uECC_make_key(public1, private1, curve);

    // shared secret test
    uint8_t private2[32];
    uint8_t public2[64];
    uECC_make_key(public2, private2, curve);

    uint8_t shared1[32], shared2[32];
    uECC_shared_secret(public2, private1, shared1, curve);
    uECC_shared_secret(public1, private2, shared2, curve);
    printf("Shared 1: ");
    printBufferToHex(stdout, shared1,32);
    printf("Shared 2: ");
    printBufferToHex(stdout, shared2,32);

    // Sign message
    COSE_Message message1;
    cose_sign1_sign("to be signed", 12, private1, curve, &message1);

    message1.unprotectedHeader.alg = -5;
    memmove(message1.unprotectedHeader.kid, "hello", 5);
    message1.unprotectedHeader.kidSize = 5;

    // Encode message
    uint8_t messageBuf[512];
    size_t messageBufSize = cose_encode_message(message1, messageBuf, sizeof(messageBuf));
    printf("Encoded: ");
    printBufferToHex(stdout, messageBuf, messageBufSize);

    // Decode message
    COSE_Message message2;
    cose_init_header(&message2.protectedHeader);
    printf("Parse: %s\n", cose_decode_message(messageBuf, messageBufSize, &message2) ? "true" : "false");

    // Verify signature
    printf("Verify: %s\n", cose_sign1_verify(&message2, public1, curve) ? "true" : "false");

    printf("\n\n");
    return 0;
}
