#include <cose-lib.h>
#include <cborjson.h>

void printCBORToJSON(FILE *f, CborValue *value)
{
    cbor_value_to_json(f, value, CborConvertStringifyMapKeys);
    fprintf(f, "\n");
}

void printBufferToHex(FILE *f, uint8_t *buf, size_t count)
{
    int i;
    for (i = 0; i < count; i++)
    {
        fprintf(f, "%02x", buf[i]);
    }
    fprintf(f, "\n");
}
