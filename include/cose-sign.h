#ifndef COSE_SIGN_H
#define COSE_SIGN_H

#include <stdlib.h>
#include <stdint.h>
#include "cose.h"
#include "uECC.h"


size_t cose_create_sig_struct(uint8_t *, size_t, uint8_t *, size_t, uint8_t *);

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
 * This message verifies
 * @param coseMessage signed message wrapped in a sign1 cose message
 * @param publicKey private key for signing
 * @param curve curve used
 * @return Size of the output buffer 
 */
int cose_sign1_verify(COSE_Message *coseMessage, const uint8_t *, uECC_Curve);

#endif