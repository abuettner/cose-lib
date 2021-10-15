#include "cose.h"
#include "cbor.h"
#include <stdlib.h>

void cose_init_header(COSE_HEADER *out)
{
    out->alg = 0;
    out->contentType = NULL;
    out->kidSize = 0;
    out->iv = NULL;
    out->ivSize = 0;
}

size_t cose_encode_protected_header(COSE_HEADER input, uint8_t *out)
{

    uint8_t protectedBuf[128];
    CborEncoder protectedEncoder, protectedMapEncoder;
    cbor_encoder_init(&protectedEncoder, protectedBuf, sizeof(protectedBuf), 0);
    cbor_encoder_create_map(&protectedEncoder, &protectedMapEncoder, 2);

    // Algorithm
    if (input.alg != 0)
    {
        cbor_encode_int(&protectedMapEncoder, COSE_HEADER_ALG);
        cbor_encode_int(&protectedMapEncoder, input.alg);
    }
    // KID
    if (input.kidSize > 0)
    {
        cbor_encode_int(&protectedMapEncoder, COSE_HEADER_KID);
        cbor_encode_byte_string(&protectedMapEncoder, input.kid, input.kidSize);
    }

    // @TODO add other parameters
    cbor_encoder_close_container(&protectedEncoder, &protectedMapEncoder);

    memmove(out, protectedBuf, cbor_encoder_get_buffer_size(&protectedEncoder, protectedBuf));
    return cbor_encoder_get_buffer_size(&protectedEncoder, protectedBuf);
}

size_t cose_encode_message(const COSE_Message coseMessage, uint8_t *out)
{

    uint8_t buf[512];
    CborEncoder encoder, arrayEncoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);

    // Tag
    cbor_encode_tag(&encoder, coseMessage.type);

    switch (coseMessage.type)
    {
    case CborCOSE_Sign1Tag:
        cbor_encoder_create_array(&encoder, &arrayEncoder, 4);
        break;
    default:
        cbor_encoder_create_array(&encoder, &arrayEncoder, 3);
        break;
    }

    // * * * * * Protected * * * * * //
    uint8_t protectedBuf[128];
    size_t protectedBufSize = cose_encode_protected_header(coseMessage.protectedHeader, protectedBuf);
    cbor_encode_byte_string(&arrayEncoder, protectedBuf, protectedBufSize);

    // * * * * * Unprotected * * * * * //
    CborEncoder unprotectedMapEncoder;
    cbor_encoder_create_map(&arrayEncoder, &unprotectedMapEncoder, 0);
    cbor_encoder_close_container(&arrayEncoder, &unprotectedMapEncoder);

    // * * * * * Payload * * * * * //
    cbor_encode_byte_string(&arrayEncoder, coseMessage.payload, coseMessage.payloadSize);

    // * * * * * Signature * * * * * //
    if (coseMessage.type == CborCOSE_Sign1Tag)
    {
        cbor_encode_byte_string(&arrayEncoder, coseMessage.signature, sizeof(coseMessage.signature));
    }

    cbor_encoder_close_container(&encoder, &arrayEncoder);
    memmove(out, buf, cbor_encoder_get_buffer_size(&encoder, buf));
    return cbor_encoder_get_buffer_size(&encoder, buf);
}

int cose_decode_protected_header(uint8_t *input, size_t inputSize, COSE_HEADER *out)
{
    CborParser parser;
    CborValue value, mapContainer;
    cbor_parser_init(input, inputSize, 0, &parser, &value);
    if (cbor_value_is_valid(&value))
    {
        if (cbor_value_is_map(&value))
        {
            size_t mapLength;
            cbor_value_get_map_length(&value, &mapLength);
            cbor_value_enter_container(&value, &mapContainer);
            int key;
            for (int i = 0; i < mapLength; i++)
            {
                if (cbor_value_is_integer(&mapContainer))
                {
                    cbor_value_get_int(&mapContainer, &key);
                    cbor_value_advance(&mapContainer);
                    switch (key)
                    {
                    case COSE_HEADER_ALG:
                        if (cbor_value_is_integer(&mapContainer))
                        {
                            cbor_value_get_int(&mapContainer, &out->alg);
                        }
                        break;
                    case COSE_HEADER_KID:
                        if (cbor_value_is_byte_string(&mapContainer))
                        {
                            uint8_t kid[64];
                            size_t kidSize;
                            cbor_value_copy_byte_string(&mapContainer, kid, &kidSize, NULL);
                            memmove(out->kid, kid, kidSize);
                            out->kidSize = kidSize;
                        }
                        break;
                    default:
                        return 0;
                        break;
                    }
                    cbor_value_advance(&mapContainer);
                }
            }

            return 1;
        }
    }
    return 0;
}

int cose_decode_message(uint8_t *input, size_t inputSize, COSE_Message *out)
{                       
    CborParser parser;
    CborValue value, arrayContainer;
    cbor_parser_init(input, inputSize, 0, &parser, &value);
    if (cbor_value_is_valid(&value))
    {
        if (cbor_value_is_tag(&value))
        {
            // Type
            cbor_value_get_tag(&value, &out->type);
            cbor_value_advance_fixed(&value);

            if (cbor_value_is_array(&value))
            {
                size_t arrayLength;
                cbor_value_get_array_length(&value, &arrayLength);
                if (arrayLength > 2)
                {
                    cbor_value_enter_container(&value, &arrayContainer);

                    // Protected header
                    if (cbor_value_is_byte_string(&arrayContainer))
                    {
                        uint8_t *protectedBuf;
                        size_t protectedBufSize;

                        cbor_value_calculate_string_length(&arrayContainer, &protectedBufSize);
                        protectedBuf = (uint8_t *)malloc(sizeof(uint8_t) * protectedBufSize);

                        cbor_value_copy_byte_string(&arrayContainer, protectedBuf, &protectedBufSize, NULL);
                        if(!cose_decode_protected_header(protectedBuf, protectedBufSize, &out->protectedHeader)){
                            return 0;
                        }
                    }

                    cbor_value_advance(&arrayContainer);

                    // Unprotected header
                    if (cbor_value_is_map(&arrayContainer))
                    {
                        // @TODO parse header
                        //cbor_value_enter_container(&arrayContainer, &out->unprotectedHeader);
                    }
                    cbor_value_advance(&arrayContainer);

                    // Payload
                    if (cbor_value_is_byte_string(&arrayContainer))
                    {
                        cbor_value_calculate_string_length(&arrayContainer, &out->payloadSize);
                        out->payload = (uint8_t *)malloc(sizeof(uint8_t) * out->payloadSize);
                        cbor_value_copy_byte_string(&arrayContainer, out->payload, &out->payloadSize, NULL);
                    }
                    cbor_value_advance(&arrayContainer);

                    // Signature
                    if (out->type == CborCOSE_Sign1Tag && arrayLength == 4)
                    {
                        size_t s;
                        cbor_value_calculate_string_length(&arrayContainer, &s);
                        cbor_value_copy_byte_string(&arrayContainer, out->signature, &s, NULL);
                    }
                    return 1;
                }
            }
        }
    }
    return 0;
}