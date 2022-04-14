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
#include <cose-encrypt.h>

#include "uECC.h"
#include <openssl/sha.h>
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"

int main()
{
   /* const char* hexString = "aabbcc";
    uint8_t buf[16];
    int s = hexToBytes(hexString,strlen(hexString),buf,16);
    printBufferToHex(stdout, buf, s);


    
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
    printBufferToHex(stdout, shared1, 32);
    printf("Shared 2: ");
    printBufferToHex(stdout, shared2, 32);

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

    // MBEDTL AES TEST
    // aesTest();

    // MBEDTL GCM TEST
    gcmTest();

    ecdsaTest();
    
    printf("\n");*/

    uint8_t msgBuf[512];
    COSE_Message message3;
    uint8_t key[16];
    generateRandomBytes(key,sizeof(key));
    cose_encrypt0_encrypt(COSE_ENCRYPT_ALG_A256GCM, "hello", 5, key, sizeof(key), &message3);

    int msgBufSize = cose_encode_message(message3,msgBuf, sizeof(msgBuf));



    COSE_Message message4;
    //const char keyHex[] = "d461c01ad6914e8779cab58a892682b86ee9bfe40ebbe822f383c1e18c32544e";
    //const char enc0[] = "d08343a10103a204446b657931054c44a71ef7b84f47c833de2439581efa449a2c319573822901cfcdbe1f9df1ad56c27066e98b7e9cf39b358260";
    
   // uint8_t keyBytes[256];
    //uint8_t enc0Bytes[256];
    
    //int keySize = hexToBytes(keyHex,strlen(keyHex),keyBytes,sizeof(keyBytes));
    //int enc0Size = hexToBytes(enc0,strlen(enc0),enc0Bytes,sizeof(enc0Bytes));

    cose_init_header(&message4.protectedHeader); 
    cose_decode_message(msgBuf, msgBufSize, &message4);

    uint8_t plainBuf[512];
    int plainBufSize = cose_encrypt0_decrypt(&message4, key, sizeof(key),plainBuf,sizeof(plainBuf));
    printf("\nDecrypt: (%d)\n",plainBufSize);
    printf(plainBuf);
    

    ecdhTest();
    
    return 0;
}/*

void aesTest()
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    unsigned char key[32];
    unsigned char iv[16];
    unsigned char iv2[16];
    memcpy(iv2, iv, 16);

    char *input = "Hello world";
    unsigned char output[128];
    unsigned char plain[128];
    printf("%s\n", input);

    size_t input_len = 40;
    size_t output_len = 0;
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, (const unsigned char *)input, output);
    mbedtls_aes_setkey_dec(&aes, key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv2, output, plain);
    mbedtls_aes_free(&aes);
    printf("%s\n", plain);
    printf("%d\n", strlen(plain));
}

void gcmTest()
{

    mbedtls_gcm_context gcm;
    unsigned char key[32];
    unsigned char iv[16];

    char *input = "Hello world";
    unsigned char output[128];
    unsigned char plain[128];
    unsigned char tag[16];

    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, sizeof(key)*8);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 16, iv, 16, NULL, 0, input, output, 16, tag);
    mbedtls_gcm_free(&gcm);

    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, sizeof(key)*8);

    int result;
    result = mbedtls_gcm_auth_decrypt(&gcm, 16, iv, 16, NULL, 0, tag, 16, output, plain);
    mbedtls_gcm_free(&gcm);
    printf("\n");
    printf("%d\n", result);
    printf("%s\n", plain);
}
*/
void ecdsaTest()
{

    int ret = 1;

    // Generating RNG
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init(&ctr_drbg );
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL,
                                     0)) != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }

    printf(" ok\n  . Generating key pair...");


    // Generating key pair
    mbedtls_ecdsa_context ecdsaSign;
    const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdsa_init(&ecdsaSign);

    if ((ret = mbedtls_ecdsa_genkey(&ecdsaSign, curve_info->grp_id,
                                    mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf(" failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret);
    }
}


void ecdhTest()
{
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ecdh_context ecdh;
    mbedtls_ecdh_init(&ecdh);

    mbedtls_mpi d;
    mbedtls_mpi_init(&d);

    mbedtls_ecp_point q;
    mbedtls_ecp_point_init(&q);

    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg );
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL,
                                     0)) != 0)
    {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    }

    mbedtls_ecdh_gen_public(&ecdh,&d,&q,mbedtls_ctr_drbg_random, &ctr_drbg);
    
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&q);
    mbedtls_entropy_free(&entropy);
}