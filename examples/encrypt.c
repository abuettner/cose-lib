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
#include <cose-key.h>
#include <cose-lib.h>
#include <cose-encrypt.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/error.h>

int main()
{


    uint8_t kek1[32];
    generateRandomBytes(kek1, sizeof(kek1));

    uint8_t dk[16] = {0};
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),NULL,0,kek1,sizeof(kek1),NULL,0,dk,16);
    
    uint8_t err[128];
    mbedtls_strerror(ret,err, sizeof(err));
    printf("%s\n",err);
    printBufferToHex(stdout,dk,sizeof(dk));
    /*printf("First example: \n");
    example_encrypt();
    printf("\nSecond example: \n");
    example_external_data();*/
    return 0;
}

void example_encrypt()
{
    char *data = "Secret message";

    uint8_t kek1[32];
    generateRandomBytes(kek1, sizeof(kek1));

    uint8_t kek2[32];
    generateRandomBytes(kek2, sizeof(kek2));
    uint8_t kek3[32];
    generateRandomBytes(kek3, sizeof(kek3));

    COSE_Key symKey1;
    cose_init_key(&symKey1);
    symKey1.kty = COSE_KEY_TYPE_Symmetric;
    symKey1.alg = COSE_ENCRYPT_ALG_A256GCM;
    memcpy(symKey1.kid, "kidFirst", 8);
    symKey1.kidSize = 8;
    memcpy(symKey1.k, kek1, sizeof(kek1));
    symKey1.kSize = sizeof(kek1);

    COSE_Key symKey2;
    cose_init_key(&symKey2);
    symKey2.kty = COSE_KEY_TYPE_Symmetric;
    symKey2.alg = COSE_ENCRYPT_ALG_A256GCM;
    memcpy(symKey2.kid, "kidSecond", 9);
    symKey2.kidSize = 9;
    memcpy(symKey2.k, kek2, sizeof(kek2));
    symKey2.kSize = sizeof(kek2);

    COSE_Key symKey3;
    cose_init_key(&symKey3);
    symKey3.kty = COSE_KEY_TYPE_Symmetric;
    symKey3.alg = COSE_ENCRYPT_ALG_A256GCM;
    memcpy(symKey3.kid, "kidNew", 6);
    symKey3.kidSize = 9;
    memcpy(symKey3.k, kek3, sizeof(kek3));
    symKey3.kSize = sizeof(kek3);

    COSE_Key recipientKeys[2];
    recipientKeys[0] = symKey1;
    recipientKeys[1] = symKey2;

    // Encrypt message
    COSE_Message messageSend;
    cose_encrypt_encrypt(COSE_ENCRYPT_ALG_A192GCM, data, strlen(data), recipientKeys, 2, &messageSend);

    // Encode message
    uint8_t messageBuf[256];
    int messageBufSize = cose_encode_message(messageSend, messageBuf, sizeof(messageBuf));
    printf("Encoded 1: ");
    printBufferToHex(stdout, messageBuf, messageBufSize);

    // Decode message
    COSE_Message messageReceive;
    cose_decode_message(messageBuf, messageBufSize, &messageReceive);

    // Decrypt message

    uint8_t plain[strlen(data)];
    int l = cose_encrypt_decrypt(&messageReceive, &symKey2, plain, sizeof(plain));
    if (l > 0)
    {
        printf("Decrypted: %s\n", plain);
    }
    else
    {
        printf("Could not decrypt");
    }
}

void example_external_data()
{
    // Test with go message example
    const char *symKeyHex = "a5010402446b65793103010482030420500139a253ed25e0aa4482d416bc8fc331";
    const char *coseMessageHex = "d8608443a10101a1054ccd822c8b34379ed60ec016815609addc02c0208115fa0791a2d07cbf1ebbb9bf3defb0838343a10101a204446b657931054c7e36c8a653828c0dc79f0a3258206a75049e42b972b8f9fe472ce1bb030daaf48521c22eca9e82ee2403ac111d5f8343a10101a204446b657932054c01a0bd8f4f13dc310f8e380158201be453f9b698c71bc3b4bb3ee086d281d404fb8907ebda082a4d243fa2133a9f8343a10101a204446b657933054ce856dd276f8b894c16fe0072582006b414ab2a4645d973e5b3360b6a163ae2dd0ba8ad782609b39a384a8fb35ab5";

    uint8_t symKeyBuf[strlen(symKeyHex) / 2];
    size_t symKeySize = hexToBytes(symKeyHex, strlen(symKeyHex), symKeyBuf, sizeof(symKeyBuf));

    uint8_t coseMessageBuf[strlen(coseMessageHex) / 2];
    size_t coseMessageSize = hexToBytes(coseMessageHex, strlen(coseMessageHex), coseMessageBuf, sizeof(coseMessageBuf));

    COSE_Key sk;
    cose_decode_key(symKeyBuf, symKeySize, &sk);

    COSE_Message msg;
    cose_decode_message(coseMessageBuf, coseMessageSize, &msg);

    uint8_t plain2[24];
    int l = cose_encrypt_decrypt(&msg, &sk, plain2, sizeof(plain2));
    if (l > 0)
    {
        printf("Decrypted: %s\n", plain2);
    }
    else
    {
        printf("Could not decrypt");
    }
}