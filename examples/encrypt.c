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

int main()
{
    char *data = "Secret message";

    uint8_t kek1[16];
    generateRandomBytes(kek1, sizeof(kek1));

    uint8_t kek2[16];
    generateRandomBytes(kek2, sizeof(kek2));
    uint8_t kek3[16];
    generateRandomBytes(kek3, sizeof(kek3));

    COSE_Key symKey1;
    cose_init_key(&symKey1);
    symKey1.kty = COSE_KEY_TYPE_Symmetric;
    symKey1.alg = COSE_ENCRYPT_ALG_A128GCM;
    memcpy(symKey1.kid, "kidFirst", 8);
    symKey1.kidSize = 8;
    memcpy(symKey1.k, kek1, sizeof(kek1));
    symKey1.kSize = sizeof(kek1);

    COSE_Key symKey2;
    cose_init_key(&symKey2);
    symKey2.kty = COSE_KEY_TYPE_Symmetric;
    symKey2.alg = COSE_ENCRYPT_ALG_A128GCM;
    memcpy(symKey2.kid, "kidSecond", 9);
    symKey2.kidSize = 9;
    memcpy(symKey2.k, kek2, sizeof(kek2));
    symKey2.kSize = sizeof(kek2);

    COSE_Key symKey3;
    cose_init_key(&symKey3);
    symKey3.kty = COSE_KEY_TYPE_Symmetric;
    symKey3.alg = COSE_ENCRYPT_ALG_A128GCM;
    memcpy(symKey3.kid, "kidNew", 6);
    symKey3.kidSize = 9;
    memcpy(symKey3.k, kek3, sizeof(kek3));
    symKey3.kSize = sizeof(kek3);

    COSE_Key recipientKeys[2];
    recipientKeys[0] = symKey1;
    recipientKeys[1] = symKey2;

    // Encrypt message
    COSE_Message messageSend;
    cose_encrypt_encrypt(COSE_ENCRYPT_ALG_A128GCM, data, strlen(data), recipientKeys, 2, &messageSend);

    // Encode message
    uint8_t messageBuf[256];
    int messageBufSize = cose_encode_message(messageSend, messageBuf, sizeof(messageBuf));
    printf("Encoded 1: ");
    printBufferToHex(stdout, messageBuf, messageBufSize);
    

    // Decode message
    COSE_Message messageReceive;
    cose_decode_message(messageBuf, messageBufSize, &messageReceive);

    /*
    uint8_t messageBuf2[256];

    printf("Encoded 2: ");
    int messageBuf2Size = cose_encode_message(messageReceive, messageBuf2, sizeof(messageBuf2));
    printBufferToHex(stdout, messageBuf2, messageBuf2Size);*/


    // Decrypt message

    uint8_t plain[strlen(data)];
    int l = cose_encrypt_decrypt(&messageReceive, &symKey2, plain, sizeof(plain));
    printf("Result: %d\n", l);
    if (l > 0)
    {
        printf("Decrypted: %s\n", plain);
    }

    return 0;
}