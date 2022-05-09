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

#ifndef COSE_H
#define COSE_H

#include <cbor.h>

enum COSE_HEADER_TAG
{
    COSE_HEADER_ALG = 1,
    COSE_HEADER_CRIT = 2,
    COSE_HEADER_CONTENT_TYPE = 3,
    COSE_HEADER_KID = 4,
    COSE_HEADER_IV = 5,
    COSE_HEADER_PARTIAL_IV = 6,
    COSE_HEADER_COUNTER_SIGNATURE = 7
};

typedef struct
{
    int alg;
    char *contentType;
    uint8_t kid[64];
    size_t kidSize;
    uint8_t iv[64];
    size_t ivSize;

} COSE_HEADER;

typedef struct
{


} COSE_RECIPIENT;

typedef struct
{
    CborTag type;
    uint8_t protectedHeaderRaw[128];
    size_t protectedHeaderRawSize;
    COSE_HEADER protectedHeader;
    COSE_HEADER unprotectedHeader;
    uint8_t payload[128];
    size_t payloadSize;
    uint8_t signature[64];
    size_t recipientSize;
    COSE_RECIPIENT *recipients;

} COSE_Message;

void cose_init_header(COSE_HEADER *);
int cose_encode_header(COSE_HEADER, CborEncoder *);
int cose_decode_header(CborValue *, COSE_HEADER *);
size_t cose_encode_message(COSE_Message, uint8_t *, int);
int cose_decode_protected_header(uint8_t *, size_t, COSE_HEADER *);
int cose_decode_message(uint8_t *, size_t, COSE_Message *);

#endif