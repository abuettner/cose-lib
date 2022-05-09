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
#ifndef COSE_KEY_H
#define COSE_KEY_H

#include <cbor.h>
#include <stdlib.h>

typedef enum
{
    COSE_KEY_KTY = 1,
    COSE_KEY_KID = 2,
    COSE_KEY_ALG = 3,
    COSE_KEY_KEYOPS = 4,
    COSE_KEY_BASEIV = 5,
    COSE_KEY_K_OR_CRV = -1,
    COSE_KEY_X = -2,
    COSE_KEY_Y = -3,
    COSE_KEY_D = -4
} COSE_KEY_TAG;

typedef enum
{
    COSE_KEY_TYPE_OKP = 1,
    COSE_KEY_TYPE_EC2 = 2,
    COSE_KEY_TYPE_Symmetric = 4,
    COSE_KEY_TYPE_Reserved = 0
} COSE_KEY_TYPE;

typedef enum
{
    COSE_KEY_OPS_Sign = 1,
    COSE_KEY_OPS_Verify = 2,
    COSE_KEY_OPS_Encrypt = 3,
    COSE_KEY_OPS_Decrypt = 4,
    COSE_KEY_OPS_WrapKey = 5,
    COSE_KEY_OPS_UnwrapKey = 6,
    COSE_KEY_OPS_DeriveKey = 7,
    COSE_KEY_OPS_DeriveBits = 8,
    COSE_KEY_OPS_MacCreate = 9,
    COSE_KEY_OPS_MacVerify = 10
} COSE_KEY_OPS;

typedef struct
{
    int kty;
    uint8_t kid[12];
    size_t kidSize;
    int alg;
    int keyOps[10];
    int keyOpsNum;
    uint8_t baseIV[12];
    size_t baseIVSize;

    // Symmetric
    uint8_t k[32];
    size_t kSize;

    // Asymmetric
    int crv;
    uint8_t x[64];
    size_t xSize;
    uint8_t y[64];
    size_t ySize;
    uint8_t d[64];
    size_t dSize;

} COSE_Key;

/**
 * @brief Initialize COSE Key with default values. Must always be called right after declaration of a COSE Key struct.
 *
 * @param coseKey COSE Key struct to be initialized
 */
void cose_init_key(COSE_Key *coseKey);

/**
 * @brief Determine number of parameters used by this COSE Key struct. Required for creating CBOR map.
 *
 * @param coseKey COSE Key struct
 * @return int Number of parameters.
 */
int cose_key_size(COSE_Key *coseKey);

/**
 * @brief This function converts a COSE Key struct into a CBOR encoded byte array.
 *
 * @param coseKey COSE Key object to be encoded
 * @param output Output buffer
 * @param outputSize Output buffer size
 * @return size_t Returns size of the encoded data or -1 on error.
 */
size_t cose_encode_key(COSE_Key *coseKey, uint8_t *output, int outputSize);

/**
 * @brief This function converts a CBOR encoded byte array into a COSE Key struct.
 *
 * @param input Input buffer
 * @param inputSize Size of the encoded data
 * @param coseKey Output COSE Key struct
 * @return int Returns 1 on success and 0 on error.
 */
int cose_decode_key(uint8_t *input, size_t inputSize, COSE_Key *coseKey);

#endif