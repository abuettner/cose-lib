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
#ifndef COSE_SIGN_H
#define COSE_SIGN_H

#include <stdlib.h>
#include <stdint.h>
#include "cose.h"
#include "uECC.h"

/**
 * This function creates a sign1 cose message.
 * @param payload payload to be signed
 * @param payloadSize size of the payload
 * @param privateKey private key for signing
 * @param curve curve used
 * @param output output buffer for cose encoded message
 * @return Size of the output buffer 
 */
void cose_sign1_sign(uint8_t *, size_t, const uint8_t *, uECC_Curve, COSE_Message *);

/**
 * This message verifies a sign1 cose message.
 * @param coseMessage signed message wrapped in a sign1 cose message
 * @param publicKey private key for signing
 * @param curve curve used
 * @return Size of the output buffer 
 */
int cose_sign1_verify(COSE_Message *coseMessage, const uint8_t *, uECC_Curve);

#endif