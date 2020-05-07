//
// Created by Sun on 2020/1/6.
//

#ifndef ENCRYPT_RSAENCRYPT_H
#define ENCRYPT_RSAENCRYPT_H

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define read_rsa(type, name) RSA* sun_read_##name(type *in, RSA **rsa){return PEM_read_##name(in, rsa, NULL, NULL);}
#define read_rsa(type, name) RSA* sun_read_##name(type *in, RSA **rsa){return PEM_read_##name(in, rsa, NULL, NULL);}
#define PROJ_RSA_PADDING_TYPE RSA_PKCS1_PADDING

RSA *getRSAFromBuf(const char *buff, short int keyFmt);

RSA *getRSAFromFile(const char *fileName, short int keyFmt);

int publicEncrypt(RSA *rsa, const char *plainText, char *cipher, int plainLength);

int privateDecrypt(RSA *rsa, const char *cipherText, char *plain, int cipherLength);
//int encryptInGroup();
int encryptInGroup(RSA *rsa, const char *plain, char *cipher, int plainSize);

//int decryptInGroup();
int decryptInGroup(RSA *rsa, const char *cipher, char *plain, int cipherSize);

int keyGen(int size, char *keyPair);

//typedef struct padding_size_st {
//    int padding;
//    int size;
//} PADDING_SIZE;

typedef RSA *(*RSAInputFunc)(void *fl, RSA *x);

#endif //ENCRYPT_RSAENCRYPT_H
