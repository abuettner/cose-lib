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
#ifndef COSE_ENCRYPT_H
#define COSE_ENCRYPT_H

#include <stdlib.h>
#include <cose-key.h>

typedef enum
{
    COSE_ENCRYPT_ALG_A128GCM = 1,
    COSE_ENCRYPT_ALG_A192GCM = 2,
    COSE_ENCRYPT_ALG_A256GCM = 3,
    COSE_ENCRYPT_ALG_AES_CCM_16_64_128 = 10,
    COSE_ENCRYPT_ALG_AES_CCM_16_64_256 = 11,
    COSE_ENCRYPT_ALG_AES_CCM_64_64_128 = 12,
    COSE_ENCRYPT_ALG_AES_CCM_64_64_256 = 13,
    COSE_ENCRYPT_ALG_ChaCha20_Poly1305 = 24,
    COSE_ENCRYPT_ALG_AES_CCM_16_128_128 = 30,
    COSE_ENCRYPT_ALG_AES_CCM_16_128_256 = 31,
    COSE_ENCRYPT_ALG_AES_CCM_64_128_128 = 32,
    COSE_ENCRYPT_ALG_AES_CCM_64_128_256 = 33
} COSE_ENCRYPT_ALG;

int cose_encrypt0_encrypt(COSE_ENCRYPT_ALG alg, uint8_t *payload, size_t payloadSize, uint8_t *key, size_t keySize, uint8_t *kid, size_t kidSize, COSE_Message *coseMessage);
int cose_encrypt0_decrypt(COSE_Message *coseMessage, uint8_t *key, size_t keySize, uint8_t *buf, size_t bufSize);
int cose_encrypt_encrypt(COSE_ENCRYPT_ALG alg, uint8_t *payload, size_t payloadSize, COSE_Key *keys, int numKeys, COSE_Message *coseMessage);
int cose_encrypt_decrypt(COSE_Message *coseMessage, COSE_Key *key, uint8_t *buf, size_t bufSize);

#endif