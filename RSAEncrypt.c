//
// Created by Sun on 2020/1/6.
//

#include "RSAEncrypt.h"

read_rsa(FILE, RSAPrivateKey)
//sun_re
read_rsa(FILE, RSAPublicKey)

read_rsa(FILE, RSA_PUBKEY)

read_rsa(BIO, bio_RSAPrivateKey)

read_rsa(BIO, bio_RSAPublicKey)

read_rsa(BIO, bio_RSA_PUBKEY)

RSA *(*(bioFuncV2[3]))(BIO *bio, RSA **x) = {
        sun_read_bio_RSAPrivateKey,
        sun_read_bio_RSAPublicKey,
        sun_read_bio_RSA_PUBKEY,
};

RSA *(*(fileReadFuncV2[3]))(FILE *fl, RSA **x) = {
        sun_read_RSAPrivateKey,
        sun_read_RSAPublicKey,
        sun_read_RSA_PUBKEY
};

RSA *getRSAFromBuf(const char *buff, short int keyFmt) {
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(buff, -1);
    if (bio != NULL) {
        rsa = RSA_new();
        bioFuncV2[keyFmt](bio, &rsa);
        BIO_free_all(bio);
    }
    return rsa;
}

RSA *getRSAFromFile(const char *fileName, short int keyFmt) {
    RSA *rsa = NULL;
    if (0 <= keyFmt && keyFmt < 3) {
        FILE *fp = fopen(fileName, "rb");
        if (fp != NULL) {
            fileReadFuncV2[keyFmt](fp, &rsa);
        } else printf("file open error:{%s}\n", fileName);
        fclose(fp);
    }
    return rsa;
}

int publicEncrypt(RSA *rsa, const char *plainText, char *cipher, const int plainSize) {
    int len = RSA_size(rsa), ret = -1;
    if (cipher != NULL) {
        memset(cipher, 0, len + 1);
        ret = RSA_public_encrypt(plainSize, (const unsigned char *) plainText,
                                 (unsigned char *)cipher, rsa, PROJ_RSA_PADDING_TYPE);
    }
    return ret;
}

int privateDecrypt(RSA *rsa, const char *cipherText, char *plain, const int cipherSize) {

    int len = RSA_size(rsa), ret = -1;
    unsigned char *plainBuf = (unsigned char *) malloc(len);
    if (plainBuf != NULL) {
        memset(plainBuf, 0, len);
        ret = RSA_private_decrypt(cipherSize, (const unsigned char *) cipherText,
                                  plainBuf, rsa, PROJ_RSA_PADDING_TYPE);

        if (ret > 0)
            memcpy(plain, plainBuf, ret);
        free(plainBuf);
    }
    return ret;
}

int keyGen(int bits, char *keyPair) {
    RSA *rsa = RSA_new();
    BIGNUM *bignum = BN_new();
    RSA_generate_key_ex(rsa, bits, bignum, NULL);
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
//    BIO_read
    return 0;
}

int getPaddingSize(int padding) {
    int paddingSize[6] = {0};
    paddingSize[RSA_PKCS1_PADDING] = RSA_PKCS1_PADDING_SIZE; // 1 : 11
    paddingSize[RSA_SSLV23_PADDING] = 11;
    paddingSize[RSA_NO_PADDING] = 0;
    paddingSize[RSA_PKCS1_OAEP_PADDING] = SHA_DIGEST_LENGTH * 2 - 2;
    paddingSize[RSA_X931_PADDING] = 2;

    return paddingSize[padding];
}

int encryptInGroup(RSA *rsa, const char *plain, char *cipher, const int plainSize) {
    int groupSize = RSA_size(rsa) - getPaddingSize(PROJ_RSA_PADDING_TYPE);
    int cipherSize = 0;
    for (int i = 0; i < plainSize; i += groupSize) {
        const char *buf = plain + i;
        int bufSize = i + groupSize < plainSize ? groupSize : plainSize - i;
        if (bufSize)
            cipherSize += publicEncrypt(rsa, buf, cipher + cipherSize, bufSize);
    }
    return cipherSize;
}


int decryptInGroup(RSA *rsa, const char *cipher, char *plain, const int cipherSize) {
    int groupSize = RSA_size(rsa);
    int plainSize = 0;
    for (int i = 0; i < cipherSize; i += groupSize) {
        const char *buf = cipher + i;
        int bufSize = i + groupSize >= cipherSize ? cipherSize - i : groupSize;
        if (bufSize)
            plainSize += privateDecrypt(rsa, buf, plain + plainSize, bufSize);
    }
    return plainSize;
}
