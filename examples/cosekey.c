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
#include <cose-encrypt.h>
#include <cose-sign.h>
#include <cose-key.h>
#include <cose-lib.h>

//const char *symKeyHex = "a60104024d656e6372797074696f6e4b650d03010482030405483132333435363738204a7365637265742d6b6579";
const char *symKeyHex = "a5010402446b65793103010482030420507103d607491ae0beb0811ff43b625c55";
//const char *signKeyHex = "a8010202477369676e4b657903260481012001214164224100234100";
const char *signKeyHex = "a7010203260481072001215820eb49da0ed8a5914ae4da65953a4a20933c15859955ed1f95ff50bdb4b8193e3c225820891bb286d99fece69db3773eaa0b634739bf87417d3dbc48207d876445b990c723582087733d64271bf63866195cc8ae79daa853c48d1c75ced5d18afd27a221e8f8ad";

int main()
{
    uint8_t symKey[strlen(symKeyHex) / 2];
    size_t symKeySize = hexToBytes(symKeyHex, strlen(symKeyHex), symKey, sizeof(symKey));

    printf("Symmetric key encode: ");
    symkey_encode_example();

    printf("Symmetric key decode: ");
    symkey_decode_example(symKey, sizeof(symKey));

    printf("EC2 key encode: ");
    asymkey_encode_example();

    printf("EC2 key decode: ");
    uint8_t signKey[strlen(signKeyHex) / 2];
    size_t signKeySize = hexToBytes(signKeyHex, strlen(signKeyHex), signKey, sizeof(signKey));
    asymkey_decode_example(signKey, sizeof(signKey));
    return 0;
}

void symkey_encode_example()
{
    uint8_t buf[128];
    COSE_Key coseKey;
    cose_init_key(&coseKey);

    coseKey.kty = COSE_KEY_TYPE_Symmetric;

    memcpy(coseKey.kid, "encryptionKey", 13);
    coseKey.kidSize = 13;

    coseKey.alg = COSE_ENCRYPT_ALG_A128GCM;

    coseKey.keyOps[0] = COSE_KEY_OPS_Encrypt;
    coseKey.keyOps[1] = COSE_KEY_OPS_Decrypt;
    coseKey.keyOpsNum = 2;

    memcpy(coseKey.baseIV, "12345678", 8);
    coseKey.baseIVSize = 8;

    memcpy(coseKey.k, "secret-key", 10);
    coseKey.kSize = 10;

    size_t dataSize = cose_encode_key(&coseKey, buf, sizeof(buf));
    printBufferToHex(stdout, buf, dataSize);
}

void symkey_decode_example(uint8_t *buf, size_t bufSize)
{

    // Decoding
    uint8_t buf2[128];

    COSE_Key decCoseKey;
    cose_init_key(&decCoseKey);
    cose_decode_key(buf, bufSize, &decCoseKey);

    size_t dataSize = cose_encode_key(&decCoseKey, buf2, sizeof(buf2));
    printBufferToHex(stdout, buf2, dataSize);
}

void asymkey_encode_example()
{
    uint8_t buf[128];
    COSE_Key coseKey;
    cose_init_key(&coseKey);

    coseKey.kty = COSE_KEY_TYPE_EC2;

    memcpy(coseKey.kid, "signKey", 7);
    coseKey.kidSize = 7;

    coseKey.alg = COSE_SIGN_ALG_ES256;

    coseKey.keyOps[0] = COSE_KEY_OPS_Sign;
    coseKey.keyOpsNum = 1;

    coseKey.crv = 1;
    memcpy(coseKey.x, "x", 1);
    coseKey.xSize = 1;
    memcpy(coseKey.x, "y", 1);
    coseKey.ySize = 1;
    memcpy(coseKey.x, "d", 1);
    coseKey.dSize = 1;

    size_t dataSize = cose_encode_key(&coseKey, buf, sizeof(buf));
    printBufferToHex(stdout, buf, dataSize);
}

void asymkey_decode_example(uint8_t *buf, size_t bufSize)
{
    // Decoding
    uint8_t buf2[128];

    COSE_Key decCoseKey;
    cose_init_key(&decCoseKey);
    cose_decode_key(buf, bufSize, &decCoseKey);

    size_t dataSize = cose_encode_key(&decCoseKey, buf2, sizeof(buf2));
    printBufferToHex(stdout, buf2, dataSize);
}