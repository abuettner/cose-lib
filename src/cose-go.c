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

#include "cose.h"
#include "cose-lib.h"
#include "cose-sign.h"
#include "cose-go.h"
#include "uECC.h"

void cose_make_key_go(void *privateKeyBuf, void *publicKeyBuf)
{
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uECC_make_key(publicKeyBuf, privateKeyBuf, curve);
}

int cose_sign1_sign_go(void *payload, size_t payloadSize, void *privateKey, void *output, size_t outputSize)
{
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    COSE_Message message;
    cose_sign1_sign((uint8_t *)payload, payloadSize, (uint8_t *)privateKey, curve, &message);

    return (int)cose_encode_message(message, output, outputSize);
}

int cose_sign1_verify_go(void *messageBuf, size_t messageBufSize, void *publicKey)
{
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    COSE_Message message;
    cose_init_header(&message.protectedHeader);
    if (cose_decode_message(messageBuf, messageBufSize, &message))
    {
        return cose_sign1_verify(&message, publicKey, curve);
    }
    printf("error\n");

    return 0;
}