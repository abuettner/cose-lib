#include "cose.h"
#include "cbor.h"
#include <stdlib.h>

void cose_init_header(COSE_HEADER *output)
{
    output->alg = 0;
    output->contentType = NULL;
    output->kidSize = 0;
    output->ivSize = 0;
}

int cose_header_size(COSE_HEADER input)
{
    int count = 0;
    if (input.alg != 0)
        count++;

    if (input.contentType != NULL)
        count++;

    if (input.kidSize > 0)
        count++;

    if (input.ivSize > 0)
        count++;

    return count;
}

int cose_encode_header(COSE_HEADER input, CborEncoder *encoder)
{
    CborEncoder mapEncoder;
    cbor_encoder_create_map(encoder, &mapEncoder, cose_header_size(input));

    // Algorithm
    if (input.alg != 0)
    {
        cbor_encode_int(&mapEncoder, COSE_HEADER_ALG);
        cbor_encode_int(&mapEncoder, input.alg);
    }
    // KID
    if (input.kidSize > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_HEADER_KID);
        cbor_encode_byte_string(&mapEncoder, input.kid, input.kidSize);
    }

    // @TODO add other parameters
    cbor_encoder_close_container(encoder, &mapEncoder);

    return 1;
}

size_t cose_encode_message(COSE_Message coseMessage, uint8_t *outBuf, int outBufSize)
{
    CborEncoder encoder, arrayEncoder;
    cbor_encoder_init(&encoder, outBuf, outBufSize, 0);

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
    CborEncoder protectedEncoder;
    cbor_encoder_init(&protectedEncoder, protectedBuf, sizeof(protectedBuf), 0);
    cose_encode_header(coseMessage.protectedHeader, &protectedEncoder);
    size_t protectedBufSize = cbor_encoder_get_buffer_size(&protectedEncoder, protectedBuf);

    cbor_encode_byte_string(&arrayEncoder, protectedBuf, protectedBufSize);

    // * * * * * Unprotected * * * * * //
    cose_encode_header(coseMessage.unprotectedHeader, &arrayEncoder);

    // * * * * * Payload * * * * * //
    cbor_encode_byte_string(&arrayEncoder, coseMessage.payload, coseMessage.payloadSize);

    // * * * * * Signature * * * * * //
    if (coseMessage.type == CborCOSE_Sign1Tag)
    {
        cbor_encode_byte_string(&arrayEncoder, coseMessage.signature, sizeof(coseMessage.signature));
    }

    cbor_encoder_close_container(&encoder, &arrayEncoder);
    return cbor_encoder_get_buffer_size(&encoder, outBuf);
}

int cose_decode_header(CborValue *value, COSE_HEADER *out)
{
    CborValue mapContainer;
    if (cbor_value_is_valid(value))
    {
        if (cbor_value_is_map(value))
        {
            printf("Test 2\n");
            size_t mapLength;
            cbor_value_get_map_length(value, &mapLength);
            cbor_value_enter_container(value, &mapContainer);
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
                            printf("\nAlg: %d", out->alg);
                            printf("\n");
                        }
                        break;
                    case COSE_HEADER_KID:
                        if (cbor_value_is_byte_string(&mapContainer))
                        {
                            uint8_t kid[64];
                            size_t kidSize;
                            cbor_value_calculate_string_length(&mapContainer, &kidSize);
                            cbor_value_copy_byte_string(&mapContainer, kid, &kidSize, NULL);

                            printf("\nKid: ");
                            printBufferToHex(stdout, kid, kidSize);
                            printf("\n");
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
                        cbor_value_calculate_string_length(&arrayContainer, &out->protectedHeaderRawSize);
                        cbor_value_copy_byte_string(&arrayContainer, out->protectedHeaderRaw, &out->protectedHeaderRawSize, NULL);
                        CborParser protectedParser;
                        CborValue protectedValue;
                        cbor_parser_init(out->protectedHeaderRaw, out->protectedHeaderRawSize, 0, &protectedParser, &protectedValue);

                        printf("Protected raw 1: ");
                        printBufferToHex(stdout, out->protectedHeaderRaw, out->protectedHeaderRawSize);
                       
                        if (!cose_decode_header(&protectedValue, &out->protectedHeader))
                        {
                            return 0;
                        }
                    }

                    cbor_value_advance(&arrayContainer);

                    // Unprotected header
                    if (cbor_value_is_map(&arrayContainer))
                    {
                        if (!cose_decode_header(&arrayContainer, &out->unprotectedHeader))
                        {
                            return 0;
                        }
                    }
                    cbor_value_advance(&arrayContainer);

                    // Payload
                    if (cbor_value_is_byte_string(&arrayContainer))
                    {
                        cbor_value_calculate_string_length(&arrayContainer, &out->payloadSize);
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