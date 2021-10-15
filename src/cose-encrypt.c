
#include <stdlib.h>
#include <cbor.h>

#include <cose.h>
#include <cose-lib.h>
#include <cose-encrypt.h>

ssize_t convert_hex(uint8_t *dest, size_t count, const char *src)
{
    size_t i;
    int value;
    for (i = 0; i < count && sscanf(src + i * 2, "%2x", &value) == 1; i++)
    {
        dest[i] = value;
    }
    return i;
}

ssize_t cose_encrypt0(COSE_ENCRYPT_ALG alg)
{
    /*uint8_t buf[512];
    CborEncoder encoder, arrayEncoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    cose_init_message(&encoder, &arrayEncoder, CborCOSE_Encrypt0Tag);

    // * * * * * Protected * * * * * //
    uint8_t ivBuf[26];
    size_t ivLength = convert_hex(ivBuf, 26, "3030303130323033303430353036303730383039306130623063");
    uint8_t protectedBuf[512];
    CborEncoder protectedEncoder, protectedMapEncoder;
    cbor_encoder_init(&protectedEncoder, protectedBuf, sizeof(protectedBuf), 0);
    cbor_encoder_create_map(&protectedEncoder, &protectedMapEncoder, 2);
    // Algorithm
    cbor_encode_int(&protectedMapEncoder, COSE_HEADER_ALG);
    cbor_encode_int(&protectedMapEncoder, 1);
    // IV
    cbor_encode_int(&protectedMapEncoder, COSE_HEADER_IV);
    cbor_encode_byte_string(&protectedMapEncoder, ivBuf, ivLength);
    cbor_encoder_close_container(&protectedEncoder, &protectedMapEncoder);
    cose_create_protected_header(&arrayEncoder, protectedBuf, cbor_encoder_get_buffer_size(&protectedEncoder, protectedBuf));

    // * * * * * Unprotected * * * * * //
    CborEncoder unprotectedMapEncoder;
    cbor_encoder_create_map(&arrayEncoder, &unprotectedMapEncoder, 1);
    // KID
    cbor_encode_int(&unprotectedMapEncoder, COSE_HEADER_KID);
    cbor_encode_text_stringz(&unprotectedMapEncoder, "kid1");
    cbor_encoder_close_container(&arrayEncoder, &unprotectedMapEncoder);

    // cose_create_unprotected_header(&arrayEncoder);

    // * * * * * Payload * * * * * //
    uint8_t payloadBuf[35];
    size_t payloadLength = convert_hex(payloadBuf, 35, "CCA3441A2464D240E09FE9EE0EA42A7852A4F41D9945325C1F8D3B1353B8EB83E6A62F");
    cose_create_payload(&arrayEncoder, payloadBuf, payloadLength);
    cose_close_message(&encoder, &arrayEncoder);

    printf("Hex: ");
    printBufferToHex(stdout, buf, cbor_encoder_get_buffer_size(&encoder, buf));

    printf("JSON: ");

    CborParser parser;
    CborValue value;
    cbor_parser_init(buf, cbor_encoder_get_buffer_size(&encoder, buf), 0, &parser, &value);
    printCBORToJSON(stdout, &value);*/
    return 0;
}