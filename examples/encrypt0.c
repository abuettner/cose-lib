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
#include <cose-encrypt.h>


int main()
{
    char* data = "Secret message";

    uint8_t key[16];
    generateRandomBytes(key,sizeof(key));

    // Encrypt message
    COSE_Message messageSend;
    cose_encrypt0_encrypt(COSE_ENCRYPT_ALG_A256GCM, data, strlen(data), key, sizeof(key), "kid1", 4,&messageSend);

    // Encode message
    uint8_t messageBuf[128];
    int messageBufSize = cose_encode_message(messageSend, messageBuf, sizeof(messageBuf));
    printf("Encoded: ");
    printBufferToHex(stdout, messageBuf, messageBufSize);

    // Decode message
    COSE_Message messageReceive;
    cose_init_header(&messageReceive.protectedHeader); 
    printf("Decode: %s\n", cose_decode_message(messageBuf, messageBufSize, &messageReceive) ? "true" : "false");

    uint8_t plainBuf[512];
    int plainBufSize = cose_encrypt0_decrypt(&messageReceive, key, sizeof(key),plainBuf,sizeof(plainBuf));
    printf("Decrypt and authenticate: %s\n", plainBufSize ? "true" : "false");

    // Get data
    printf("Data: %s\n", plainBuf);

    return 0;
}