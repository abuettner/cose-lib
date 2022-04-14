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

#include <stdlib.h>
#include <cbor.h>

#include <cose.h>
#include <cose-lib.h>
#include <cose-encrypt.h>

#include "mbedtls/gcm.h"
#include "mbedtls/error.h"

ssize_t convert_hex(uint8_t *dest, size_t count, const char *src)
{
    size_t i;
    int value;
    for (i = 0; i < count && sscanf(src + i * 2, "%2x", &value) == 1; i++)
    {
        dest[i] = value;
    }
    return i;
}

size_t cose_create_enc0_struct(uint8_t *protectedBuf, size_t protectedBufSize, uint8_t *enc_struct_out, size_t enc_struct_out_size)
{
    CborEncoder encStructEncoder, encStructArrayEncoder;
    cbor_encoder_init(&encStructEncoder, enc_struct_out, enc_struct_out_size, 0);
    cbor_encoder_create_array(&encStructEncoder, &encStructArrayEncoder, 3);
    cbor_encode_text_string(&encStructArrayEncoder, "Encrypt0" , 8);
    cbor_encode_byte_string(&encStructArrayEncoder, protectedBuf, protectedBufSize);
    cbor_encode_byte_string(&encStructArrayEncoder, NULL , 0);
    cbor_encoder_close_container(&encStructEncoder, &encStructArrayEncoder);
    return cbor_encoder_get_buffer_size(&encStructEncoder, enc_struct_out);
}


int cose_encrypt0_encrypt(COSE_ENCRYPT_ALG alg, uint8_t* payload, size_t payloadSize, uint8_t* key, size_t keySize, COSE_Message *coseMessage)
{
    coseMessage->type = CborCOSE_Encrypt0Tag;

    // Protected header
    cose_init_header(&coseMessage->protectedHeader);

    // -ALG
    coseMessage->protectedHeader.alg = alg;

    CborEncoder protectedEncoder;
    cbor_encoder_init(&protectedEncoder, coseMessage->protectedHeaderRaw, sizeof(coseMessage->protectedHeaderRaw), 0);
    cose_encode_header(coseMessage->protectedHeader, &protectedEncoder);
    coseMessage->protectedHeaderRawSize = cbor_encoder_get_buffer_size(&protectedEncoder, coseMessage->protectedHeaderRaw);

    // Unprotected header
    cose_init_header(&coseMessage->unprotectedHeader);
    // -IV
    uint8_t iv[12];
    generateRandomBytes(iv, 12);

    memmove(&coseMessage->unprotectedHeader.iv, iv, sizeof(iv));
    coseMessage->unprotectedHeader.ivSize = sizeof(iv);

    // -KID
    memmove(coseMessage->unprotectedHeader.kid, "kid2", 4);
    coseMessage->unprotectedHeader.kidSize = 4;

    // Enc struct
    uint8_t encStruct[64];
    int encStructSize  = cose_create_enc0_struct(coseMessage->protectedHeaderRaw, coseMessage->protectedHeaderRawSize, encStruct, sizeof(encStruct));
    
    // Encrypt
    mbedtls_gcm_context gcm;
    uint8_t cipher[payloadSize+16];
    uint8_t* tag = &cipher[payloadSize];
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keySize*8);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, payloadSize, iv, sizeof(iv), encStruct, encStructSize, payload, cipher, 16, tag);
    mbedtls_gcm_free(&gcm);

    // Copy cipher to message payload
    coseMessage->payloadSize = sizeof(cipher);
    memmove(coseMessage->payload, cipher, sizeof(cipher));

    return 0;
}
int cose_encrypt0_decrypt(COSE_Message *coseMessage, uint8_t* key, size_t keySize, uint8_t* buf, size_t bufSize)
{
    uint8_t encStruct[64];
    int encStructSize  = cose_create_enc0_struct(coseMessage->protectedHeaderRaw, coseMessage->protectedHeaderRawSize, encStruct, sizeof(encStruct));
    
    
    // Check alg & key size

    // Check if IV exists

    // check (<payload size> - <tag size>) <= bufSize
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, keySize*8);
    int ret = mbedtls_gcm_auth_decrypt(&gcm, coseMessage->payloadSize-16, coseMessage->unprotectedHeader.iv, coseMessage->unprotectedHeader.ivSize, encStruct, encStructSize, &coseMessage->payload[coseMessage->payloadSize-16], 16, coseMessage->payload, buf);
    mbedtls_gcm_free(&gcm);
    if(ret != 0) {
        return -1;
    }

    return coseMessage->payloadSize-16;
}