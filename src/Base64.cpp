#include "Base64.h"

const char PADDING_CHAR = '=';
const char* ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const uint8_t DECODED_ALPHBET[128] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0 };
/**
 * Given a string, this function will encode it in 64b (with padding)
 */
std::string Base64::encode(const std::string& binaryText)
{
    std::string encoded((binaryText.size() / 3 + (binaryText.size() % 3 > 0)) << 2, PADDING_CHAR);

    const char* bytes = binaryText.data();
    union
    {
        uint32_t temp = 0;
        struct
        {
            uint32_t first : 6, second : 6, third : 6, fourth : 6;
        } tempBytes;
    };
    std::string::iterator currEncoding = encoded.begin();

    for (uint32_t i = 0, lim = binaryText.size() / 3; i < lim; ++i, bytes += 3)
    {
        temp = bytes[0] << 16 | bytes[1] << 8 | bytes[2];
        (*currEncoding++) = ALPHABET[tempBytes.fourth];
        (*currEncoding++) = ALPHABET[tempBytes.third];
        (*currEncoding++) = ALPHABET[tempBytes.second];
        (*currEncoding++) = ALPHABET[tempBytes.first];
    }

    switch (binaryText.size() % 3)
    {
    case 1:
        temp = bytes[0] << 16;
        (*currEncoding++) = ALPHABET[tempBytes.fourth];
        (*currEncoding++) = ALPHABET[tempBytes.third];
        break;
    case 2:
        temp = bytes[0] << 16 | bytes[1] << 8;
        (*currEncoding++) = ALPHABET[tempBytes.fourth];
        (*currEncoding++) = ALPHABET[tempBytes.third];
        (*currEncoding++) = ALPHABET[tempBytes.second];
        break;
    }

    return encoded;
}
/**
 * Given a 64b padding-encoded string, this function will decode it.
 */
std::string Base64::decode(const std::string& base64Text)
{
    if (base64Text.empty())
        return "";

    if ((base64Text.size() & 3) != 0)
        return "";

    uint32_t numPadding = (*std::prev(base64Text.end(), 1) == PADDING_CHAR) + (*std::prev(base64Text.end(), 2) == PADDING_CHAR);

    std::string decoded((base64Text.size() * 3 >> 2) - numPadding, '.');

    union
    {
        uint32_t temp;
        char tempBytes[4];
    };
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(base64Text.data());

    std::string::iterator currDecoding = decoded.begin();

    for (uint32_t i = 0, lim = (base64Text.size() >> 2) - (numPadding != 0); i < lim; ++i, bytes += 4)
    {
        temp = DECODED_ALPHBET[bytes[0]] << 18 | DECODED_ALPHBET[bytes[1]] << 12 | DECODED_ALPHBET[bytes[2]] << 6 | DECODED_ALPHBET[bytes[3]];
        (*currDecoding++) = tempBytes[2];
        (*currDecoding++) = tempBytes[1];
        (*currDecoding++) = tempBytes[0];
    }

    switch (numPadding)
    {
    case 2:
        temp = DECODED_ALPHBET[bytes[0]] << 18 | DECODED_ALPHBET[bytes[1]] << 12;
        (*currDecoding++) = tempBytes[2];
        break;

    case 1:
        temp = DECODED_ALPHBET[bytes[0]] << 18 | DECODED_ALPHBET[bytes[1]] << 12 | DECODED_ALPHBET[bytes[2]] << 6;
        (*currDecoding++) = tempBytes[2];
        (*currDecoding++) = tempBytes[1];
        break;
    }

    return decoded;
}