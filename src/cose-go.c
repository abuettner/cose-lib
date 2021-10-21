#include "cose.h"
#include "cose-lib.h"
#include "cose-sign.h"
#include "cose-go.h"
#include "uECC.h"

void cose_make_key_go(void *privateKeyBuf, void *publicKeyBuf)
{
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uECC_make_key(publicKeyBuf, privateKeyBuf, curve);
}

int cose_sign1_sign_go(void *payload, size_t payloadSize, void *privateKey, void *output, size_t outputSize)
{
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    COSE_Message message;
    cose_sign1_sign((uint8_t *)payload, payloadSize, (uint8_t *)privateKey, curve, &message);

    return (int)cose_encode_message(message, output, outputSize);
}

int cose_sign1_verify_go(void *messageBuf, size_t messageBufSize, void *publicKey)
{
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    COSE_Message message;
    cose_init_header(&message.protectedHeader);
    if (cose_decode_message(messageBuf, messageBufSize, &message))
    {
        return cose_sign1_verify(&message, publicKey, curve);
    }
    printf("error\n");

    return 0;
}