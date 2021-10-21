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