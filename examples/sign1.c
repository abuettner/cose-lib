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

#include <cose.h>
#include <cose-lib.h>
#include <cose-sign.h>
#include "uECC.h"

int main()
{
    
    char *data = "This message must not be modified";
    
    // Generate key pair
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uint8_t private1[32];
    uint8_t public1[64];
    uECC_make_key(public1, private1, curve);

    // Sign message
    COSE_Message messageSend;
    cose_sign1_sign(data, strlen(data), private1, curve, &messageSend);

    messageSend.unprotectedHeader.alg = -5;
    memmove(messageSend.unprotectedHeader.kid, "kid1", 5);
    messageSend.unprotectedHeader.kidSize = 5;

    // Encode message
    uint8_t messageBuf[128];
    size_t messageBufSize = cose_encode_message(messageSend, messageBuf, sizeof(messageBuf));
    printf("Encoded: ");
    printBufferToHex(stdout, messageBuf, messageBufSize);

    // Decode message
    COSE_Message messageReceive;
    cose_init_header(&messageReceive.protectedHeader);
    printf("Decode: %s\n", cose_decode_message(messageBuf, messageBufSize, &messageReceive) ? "true" : "false");

    // Verify signature
    printf("Verify: %s\n", cose_sign1_verify(&messageReceive, public1, curve) ? "true" : "false");

    // Get data
    printf("Data: %s\n",messageReceive.payload);
    
    return 0;
}