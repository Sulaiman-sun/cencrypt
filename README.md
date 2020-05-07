# C RSA encryption based on openssl

# 1. getRSAFromBuff

create rsa struct from key stored in memory(e.g. char*).
`buff` is the key in base64 format. `keyFmt` to specify the key format; see in [keyFmt](#keyFmt)

## 2. getRsaFromFile
the same as `getRSAFromBuf`, but read key info from local file

## 3. publicEncrypt
encrypt  `plainText` with `plainSize` bytes using `rsa`, store the result in `cipher`. return the `cipher` bytes ;
`plainSize` is supposed to be  smaller(or equal, depends on the padding methods) than `RSA key size`,  otherwise, it fails;


## 4. privateDecrypt
decrypt `cipherText` in `cipherSize` bytes by `rsa`, result is stored in `plain`, return the `plain` size;

## 5.  encryptInGroup & decryptInGroup
the same as `publicEncrypt`(`privateDectypt`),  but support  the `plainSize` larger  than `RSA key size`.  Just  as the function name, in group;


## 6. keyFmt  <span id='keyFmt'/>
specify which kind of key you are going to use:

`0` for private key, encryption and decryption are both enabled

`1` for public key in `SubjectPublicKeyInfo` structure.(starts with `BEGIN PUBLIC KEY`)

`2` for public key in `PKCS#1 RSAPublicKey` structure. (seems to start with `BEGIN RSA PUBLIC KEY`)

for `1` and `2` only encryption is enabled. without private key, decryption can not  be executed.