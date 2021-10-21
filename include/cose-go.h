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
#ifndef COSE_GO_H
#define COSE_GO_H

#include <stdlib.h>
#include <stdint.h>
#include "cose.h"


/**
 * This function creates a private and public key.
 * @param privateKeyBuf a
 * @param publicKeyBuf b
 * @return val
 */
void cose_make_key_go(void *, void *);

/**
 * This function creates a sign1 cose message.
 * @param payload payload to be signed
 * @param payloadSize size of the payload
 * @param privateKey private key for signing
 * @param output output buffer for cose encoded message
 * @param outputSize size of the output buffer
 * @return Size of the output 
 */
int cose_sign1_sign_go(void *, size_t, void *, void *, size_t);

/**
 * This function creates a sign1 cose message.
 * @param messageBuf COSE message bytes of type sign1
 * @param messageBufSize size of the COSE message bytes
 * @param publicKey public key for verifying the signature
 * @return verification result
 */
int cose_sign1_verify_go(void *, size_t, void *);

void test_go();

#endif