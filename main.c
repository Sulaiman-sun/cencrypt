#include "RSAEncrypt.h"
#include "base64.h"


void loadFile(const char *fileName, char content[]) {
    FILE *fptr = fopen(fileName, "rb");
    const int n = 128;
    char buf[n];
    if (fptr != NULL) {
        while (fgets(buf, n, (FILE *) fptr) != NULL) {
            strcat(content, buf);
            printf("%s", buf);
        }
        fclose(fptr);
    } else printf("file does not exist: %s\n", fileName);
}

RSA *runChar() {
    const char *pub = "-----BEGIN RSA PUBLIC KEY-----\n"
                      "MIGHAoGBANtaM6DwmSUdGSM6zKK0ywJ4qvLda723/mYxB9tnac5YS4+vpcjSjby6\n"
                      "by026S4I0wnOy/S3Oyb2jUJtt0rfnVjT1OPOT9eOKKmgjVkISZPB+lf4TjTl/i7U\n"
                      "z2bLn3s5I84hp2/nAc3XtSow1GToXqprtrDbkAUmie2fkHrc7t83AgED\n"
                      "-----END RSA PUBLIC KEY-----";

    const char *pri = "-----BEGIN RSA PRIVATE KEY-----\n"
                      "MIICXAIBAAKBgQDbWjOg8JklHRkjOsyitMsCeKry3Wu9t/5mMQfbZ2nOWEuPr6XI\n"
                      "0o28um8tNukuCNMJzsv0tzsm9o1CbbdK351Y09Tjzk/XjiipoI1ZCEmTwfpX+E40\n"
                      "5f4u1M9my597OSPOIadv5wHN17UqMNRk6F6qa7aw25AFJontn5B63O7fNwIBAwKB\n"
                      "gQCSPCJrSxDDaLts0d3BzdysUHH3PkfTz/7uy1qSRPE0Ot0KdRkwjF590Z9zefDJ\n"
                      "Wzdb3zKjJNIZ+bOBnnox6mjkpevbD3gX66YUC7pJRvjKYEd+YCtoLubxpYToPw2q\n"
                      "ftg5lg3U2WjpgzS+uwghMdmf2A/vmGLiKvkzwQgRwI7lawJBAPz4NQqCt9lQiCIn\n"
                      "1vQfF8TcM4DcSDItMrejFsqb3lIwTu+W2Ke7tBHGhd2//cEfKNzo+hhfWAG/QHb8\n"
                      "XLxzO7ECQQDd+uYsmPvTXwNszhQptUxssubnMNBtdpGk5POibx0oryjQ+9f5KLuB\n"
                      "H4Y6iDVceRHKtc9enFnkVN+HCAN/pUtnAkEAqKV4sax6kOBawW/kor9lLegiVegw\n"
                      "IXN3JRdkhxKUNsrfSmSQb9J4C9muk9VT1hTF6JtRZZTlVn+AT1LofaInywJBAJP8\n"
                      "mXMQp+I/V53euBvOMvMh70TLNZ5PC8NDTRb0vhsfcItSj/twfQC/rtGwI5L7YTHO\n"
                      "ij8S5pg4lQSwAlUY3O8CQCMjVx7OzxaIFgolkTM0/6X0FY1RDQt4A5MOJ3F5CZie\n"
                      "55Q3QJETre5XSPbamQBQt+9ysDFrAuxNsTO8j6BaM3M=\n"
                      "-----END RSA PRIVATE KEY-----";
    return getRSAFromBuf(pri, 0);
}

RSA *runFile() {
//    const char *priKeyName = "prikey.pem";
    const char *priKeyName = "pri_pkcs8.txt";
    return getRSAFromFile(priKeyName, 0);
}

RSA *runLoad() {
    char pub2[2048] = {0}, pri2[4096] = {0};
    loadFile("pubkey.pem", pub2);
    loadFile("prikey.pem", pri2);
    return getRSAFromBuf(pub2, 1);
}

void run(RSA *rsa, const char *msg, short int runDecrypt) {
    Base64 base64;
    initBase64(&base64);
    int cnt = 0;
    while (cnt < 1) {
        unsigned char cipher[2048] = {'\0'}, plain[2048] = {'\0'};
        char cipherB64[4096];
//        int cl = publicEncrypt(rsa, msg, cipher, (int) strlen(msg));
        int cl = encryptInGroup(rsa, msg, cipher, (int) strlen(msg));
        size_t b64Len = base64.encode(cipher, cipherB64, cl, base64.table);
        printf("cipher length: %d, cipher in base64:%s \n", cl, cipherB64);
        if (runDecrypt) {
//            int plainLen = privateDecrypt(rsa, cipher, plain, cl);
            int plainLen = decryptInGroup(rsa, cipher, plain, cl);
            printf("plain length: %d, plain: `%s`\n", plainLen, plain);

        }
        ++cnt;
    }
    RSA_free(rsa);
}


int main() {

    int size = 10;
    char msg[size];

    for (int i = 0; i < size; ++i) {
        msg[i] = 'A' + (i % 26);
    }
    msg[size - 1] = '\0';
//    run(runFile(), msg, 1);
    run(runChar(), msg, 1);
//    run(runLoad(), msg, 0);

    printf("finish\n");
    return 0;
}
