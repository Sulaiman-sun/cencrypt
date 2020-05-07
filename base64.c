//
// Created by Sun on 2020/1/11.
//

#include "base64.h"

int b64encodeV2(const unsigned char *buffer, unsigned char *b64txt,
                size_t bufferSize, const unsigned char *table) {
    unsigned byteBits = 8;
    unsigned int mvBits = 6;
    unsigned int pos;
    unsigned char extraPos;
    unsigned char maskH2 = 0x3f;
    size_t charPos = 0;
    for (size_t i = 0; i < bufferSize; ++i) {
        mvBits = (i % 3 + 1) * 2;
        pos = buffer[i] >> mvBits;
        switch (mvBits) {
            case 6:
                pos |= (buffer[i - 1] << (byteBits - mvBits)) & maskH2;    //padding high bits by previous low bits
                extraPos = buffer[i] & maskH2;  // drop high two bit;
                b64txt[charPos++] = table[pos];
                b64txt[charPos++] = table[extraPos];
                break;
            case 4:
                pos |= (buffer[i - 1] << (byteBits - mvBits)) & maskH2;
            default:
                b64txt[charPos++] = table[pos];
        }
    }
    if (mvBits != 6) {
        b64txt[charPos++] = table[(buffer[bufferSize - 1] << (6 - mvBits)) & maskH2];
    }

    while (charPos % 4) {
        b64txt[charPos++] = '=';
    }
    return charPos;
}

int b64encode(const unsigned char *buffer, unsigned char *b64txt,
              size_t bufferSize, const unsigned char *table) {
//    unsigned char keepMap[3] = {0x03, 0x0f, 0x3f};
    unsigned byteBits = 8;
    unsigned int mvBits;
    unsigned char lowBits;
    unsigned char nextHighBits = '\0';
    unsigned int pos;
    unsigned int zeroBits = 2;
    size_t charPos = 0;
    for (size_t i = 0; i < bufferSize; ++i) {
        mvBits = (i % 3 + 1) * 2;
        lowBits = buffer[i] >> mvBits;
        if (nextHighBits) {
            pos = nextHighBits | lowBits;
        } else
            pos = lowBits;
        nextHighBits = buffer[i] << (byteBits - mvBits);
        nextHighBits >>= zeroBits;    // padding high `zeroBits` bits with 0;
        b64txt[charPos++] = table[pos];
        if (mvBits == 6) {
            b64txt[charPos++] = table[nextHighBits];
            nextHighBits = 0;
        }
    }
    if (nextHighBits) {
        b64txt[charPos++] = table[nextHighBits];
    }
    while (charPos % 4) {
        b64txt[charPos++] = '=';
    }
    return charPos;
}


int b64decode(const unsigned char *b64Txt, unsigned char *plain,
              size_t b64TxtSize, const unsigned char *table) {
    size_t charPos = 0;
    unsigned step = 2;
    unsigned int mvBits;
    const int batchSize = 4, trueBits = 6;
    for (size_t i = 0; i < b64TxtSize; ++i) {
//        if (b64Txt[i] == '=') break;  // padding byte `=` means finish
        mvBits = (i % batchSize + 1) * step;
        if (mvBits == 8) continue;
        if (i + 1 == b64TxtSize || b64Txt[i + 1] == '=') {
            plain[charPos++] = table[b64Txt[i]] << mvBits; //  no valid byte remains
            break;
        } else {
            plain[charPos++] = table[b64Txt[i]] << mvBits |
                               table[b64Txt[i + 1]] >> (trueBits - mvBits);
        }
    }
    return charPos;
}

void initBase64(Base64 *base64) {
    const unsigned char table[] = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '+', '/'
    };
    memcpy(base64->table, table, 64);
    for (unsigned int i = 0; i < 64; ++i) {
        base64->decodeTable[table[i]] = i;
    }
    base64->encode = b64encode;
    base64->decode = b64decode;
    base64->_encode = b64encodeV2;
}
