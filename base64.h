//
// Created by Sun on 2020/1/11.
//

#ifndef CENCRYPT_BASE64_H
#define CENCRYPT_BASE64_H

#include <stdio.h>
#include <string.h>

typedef struct base64_st {
    int (*encode)(const unsigned char *buffer, unsigned char *b64txt, size_t bufferSize, const unsigned char *table);

    int (*decode)(const unsigned char *b64Txt, unsigned char *plain, size_t b64TxtSize, const unsigned char *table);

    int (*_encode)(const unsigned char *buffer, unsigned char *b64txt, size_t bufferSize, const unsigned char *table);


    unsigned char table[64];
    unsigned char decodeTable[123];

} Base64;

void initBase64(Base64 *base64);

#endif //CENCRYPT_BASE64_H
