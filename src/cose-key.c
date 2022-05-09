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

#include <stdlib.h>
#include <cbor.h>
#include <cose-key.h>

void cose_init_key(COSE_Key *coseKey)
{
    memset(coseKey, 0, sizeof(COSE_Key));

    //@TODO: add further key params
}

int cose_key_size(COSE_Key *coseKey)
{
    int size = 2; // Kty and alg are always set
    if (coseKey->kidSize > 0)
        size++;

    if (coseKey->keyOpsNum > 0)
        size++;

    if (coseKey->baseIVSize > 0)
        size++;

    if (coseKey->kSize > 0)
        size++;

    if (coseKey->crv != 0)
        size++;

    if (coseKey->xSize > 0)
        size++;

    if (coseKey->ySize > 0)
        size++;

    if (coseKey->dSize > 0)
        size++;

    //@TODO: add further key params

    return size;
}

size_t cose_encode_key(COSE_Key *coseKey, uint8_t *output, int outputSize)
{

    CborEncoder encoder, mapEncoder;
    cbor_encoder_init(&encoder, output, outputSize, 0);
    cbor_encoder_create_map(&encoder, &mapEncoder, cose_key_size(coseKey));

    cbor_encode_int(&mapEncoder, COSE_KEY_KTY);
    cbor_encode_int(&mapEncoder, coseKey->kty);

    if (coseKey->kidSize > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_KID);
        cbor_encode_byte_string(&mapEncoder, coseKey->kid, coseKey->kidSize);
    }

    cbor_encode_int(&mapEncoder, COSE_KEY_ALG);
    cbor_encode_int(&mapEncoder, coseKey->alg);

    if (coseKey->keyOpsNum > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_KEYOPS);
        CborEncoder arrayEncoder;
        cbor_encoder_create_array(&mapEncoder, &arrayEncoder, coseKey->keyOpsNum);
        for (int i = 0; i < coseKey->keyOpsNum; i++)
        {
            cbor_encode_int(&arrayEncoder, coseKey->keyOps[i]);
        }
        cbor_encoder_close_container(&mapEncoder, &arrayEncoder);
    }

    if (coseKey->baseIVSize > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_BASEIV);
        cbor_encode_byte_string(&mapEncoder, coseKey->baseIV, coseKey->baseIVSize);
    }

    if (coseKey->kSize > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_K_OR_CRV);
        cbor_encode_byte_string(&mapEncoder, coseKey->k, coseKey->kSize);
    }

    if (coseKey->crv != 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_K_OR_CRV);
        cbor_encode_int(&mapEncoder, coseKey->crv);
    }

    if (coseKey->xSize > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_X);
        cbor_encode_byte_string(&mapEncoder, coseKey->x, coseKey->xSize);
    }

    if (coseKey->ySize > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_Y);
        cbor_encode_byte_string(&mapEncoder, coseKey->y, coseKey->ySize);
    }

    if (coseKey->dSize > 0)
    {
        cbor_encode_int(&mapEncoder, COSE_KEY_D);
        cbor_encode_byte_string(&mapEncoder, coseKey->d, coseKey->dSize);
    }

    cbor_encoder_close_container(&encoder, &mapEncoder);

    return cbor_encoder_get_buffer_size(&encoder, output);
}

int cose_decode_key(uint8_t *input, size_t inputSize, COSE_Key *coseKey)
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
                    case COSE_KEY_KTY:
                        if (cbor_value_is_integer(&mapContainer))
                        {
                            cbor_value_get_int(&mapContainer, &coseKey->kty);
                        }
                        break;
                    case COSE_KEY_KID:
                        if (cbor_value_is_byte_string(&mapContainer))
                        {
                            cbor_value_calculate_string_length(&mapContainer, &coseKey->kidSize);
                            cbor_value_copy_byte_string(&mapContainer, coseKey->kid, &coseKey->kidSize, NULL);
                        }
                        break;
                    case COSE_KEY_ALG:
                    {
                        if (cbor_value_is_integer(&mapContainer))
                        {
                            cbor_value_get_int(&mapContainer, &coseKey->alg);
                        }
                        break;
                    }
                    case COSE_KEY_KEYOPS:
                        if (cbor_value_is_array(&mapContainer))
                        {
                            CborValue arrayContainer;
                            size_t arrayLength;
                            cbor_value_get_array_length(&mapContainer, &arrayLength);
                            cbor_value_enter_container(&mapContainer, &arrayContainer);
                            int keyOps[arrayLength];
                            for (int j = 0; j < arrayLength; j++)
                            {
                                if (cbor_value_is_integer(&arrayContainer))
                                {
                                    cbor_value_get_int(&arrayContainer, &keyOps[j]);
                                }
                                else
                                {
                                    return 0;
                                }
                                cbor_value_advance(&arrayContainer);
                            }
                            memcpy(coseKey->keyOps, keyOps, sizeof(keyOps));
                            coseKey->keyOpsNum = arrayLength;
                        }
                        break;
                    case COSE_KEY_BASEIV:
                        if (cbor_value_is_byte_string(&mapContainer))
                        {
                            cbor_value_calculate_string_length(&mapContainer, &coseKey->baseIVSize);
                            cbor_value_copy_byte_string(&mapContainer, coseKey->baseIV, &coseKey->baseIVSize, NULL);
                        }
                        break;
                    case COSE_KEY_K_OR_CRV: // can be COSE_KEY_K or COSE_KEY_CRV
                        // NEED to distinguish between K and Crv depending on KTY
                        if (coseKey->kty == COSE_KEY_TYPE_Symmetric)
                        {
                            if (cbor_value_is_byte_string(&mapContainer))
                            {
                                cbor_value_calculate_string_length(&mapContainer, &coseKey->kSize);
                                cbor_value_copy_byte_string(&mapContainer, &coseKey->k, &coseKey->kSize, NULL);
                            }
                        }
                        else if (coseKey->kty == COSE_KEY_TYPE_OKP || coseKey->kty == COSE_KEY_TYPE_EC2)
                        {
                            if (cbor_value_is_integer(&mapContainer))
                            {
                                cbor_value_get_int(&mapContainer, &coseKey->crv);
                            }
                        }
                        else
                        {
                            return 0;
                        }
                        break;
                    case COSE_KEY_X:
                        if (coseKey->kty == COSE_KEY_TYPE_OKP || coseKey->kty == COSE_KEY_TYPE_EC2)
                        {
                            if (cbor_value_is_byte_string(&mapContainer))
                            {
                                cbor_value_calculate_string_length(&mapContainer, &coseKey->xSize);
                                cbor_value_copy_byte_string(&mapContainer, &coseKey->x, &coseKey->xSize, NULL);
                            }
                        }
                        else
                        {
                            return 0; // invalid parameters
                        }
                        break;
                    case COSE_KEY_Y:
                        if (coseKey->kty == COSE_KEY_TYPE_OKP || coseKey->kty == COSE_KEY_TYPE_EC2)
                        {
                            if (cbor_value_is_byte_string(&mapContainer))
                            {
                                cbor_value_calculate_string_length(&mapContainer, &coseKey->ySize);
                                cbor_value_copy_byte_string(&mapContainer, &coseKey->y, &coseKey->ySize, NULL);
                            }
                        }
                        else
                        {
                            return 0; // invalid parameters
                        }
                        break;
                    case COSE_KEY_D:
                        if (coseKey->kty == COSE_KEY_TYPE_OKP || coseKey->kty == COSE_KEY_TYPE_EC2)
                        {
                            if (cbor_value_is_byte_string(&mapContainer))
                            {
                                cbor_value_calculate_string_length(&mapContainer, &coseKey->dSize);
                                cbor_value_copy_byte_string(&mapContainer, &coseKey->d, &coseKey->dSize, NULL);
                            }
                        }
                        else
                        {
                            return 0; // invalid parameters
                        }
                        break;
                    default:
                        return 0;
                        break;
                    }
                    cbor_value_advance(&mapContainer);
                }
            }
        }
    }

    return 1;
}