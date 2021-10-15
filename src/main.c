#include <stdio.h>
#include <cbor.h>
#include <cborjson.h>

#include <cose.h>
#include <cose-sign.h>
#include <cose-lib.h>

#include "uECC.h"
#include <openssl/sha.h>

int main()
{
    // Generate key pair
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uint8_t private1[32];
    uint8_t public1[64];
    uECC_make_key(public1, private1, curve);

    // Sign message
    COSE_Message message1;
    cose_sign1_sign("to be signed", 12, private1, curve, &message1);

    // Encode message
    uint8_t messageBuf[512];
    size_t messageBufSize = cose_encode_message(message1, messageBuf);
    printf("Encoded: \n");
    printBufferToHex(stdout, messageBuf, messageBufSize);

    // Decode message
    COSE_Message message2;
    cose_init_header(&message2.protectedHeader);
    printf("\nParse: %s\n", cose_decode_message(messageBuf, messageBufSize, &message2) ? "true" : "false");

    // Verify signature
    printf("\nVerify: %s\n", cose_sign1_verify(&message2, public1, curve) ? "true" : "false");

    return 0;
}