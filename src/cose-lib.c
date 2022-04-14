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

#include <cose-lib.h>
#include <cborjson.h>


int generateRandomBytes(uint8_t *buf, size_t size){
    int ret = 1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init(&ctr_drbg );
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL,
                                     0)) != 0)
    {
        return ret;
    }
    
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, size);
    mbedtls_ctr_drbg_free(&ctr_drbg );
    mbedtls_entropy_free(&entropy);
}


size_t hexToBytes(char* hex, size_t hexSize, uint8_t* out, size_t outSize){
    if(hexSize %2 != 0) {
        return -1;
    }
    int size = 0;
    char *pos = hex;
    for (size_t count = 0; count < hexSize/2; count++) {
        sscanf(pos, "%2hhx", &out[count]);
        pos += 2;
        size++;
    }
    return size;
}

void printCBORToJSON(FILE *f, CborValue *value)
{
    cbor_value_to_json(f, value, CborConvertStringifyMapKeys);
    fprintf(f, "\n");
}

void printBufferToHex(FILE *f, uint8_t *buf, size_t count)
{
    int i;
    for (i = 0; i < count; i++)
    {
        fprintf(f, "%02x", buf[i]);
    }
    fprintf(f, "\n");
}
