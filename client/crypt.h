
#define MD5_SUM_BITS 128
#define MD5_SUM_SIZE (MD5_SUM_BITS / 8)
#define MD5_SUM_SIZE_STR ((MD5_SUM_SIZE * 2) + 1)

#define SHA1_SUM_BITS 160
#define SHA1_SUM_SIZE (SHA1_SUM_BITS / 8)
#define SHA1_SUM_SIZE_STR ((SHA1_SUM_SIZE * 2) + 1)

#define CERTIFICATE_DIGEST_SIZE SHA1_SUM_SIZE
#define CERTIFICATE_DIGEST_SIZE_STR SHA1_SUM_SIZE_STR

#define RSA_MAGIC_PUB  0x31415352 // 'RSA1'
#define RSA_MAGIC_PRIV 0x32415352 // 'RSA2'

BOOL CertDigest(PCCERT_CONTEXT pCertContext, char *lpszDigest);
BOOL CertLoad(PVOID Data, DWORD dwDataSize, PCCERT_CONTEXT *pRetCertContext);

DWORD CryptRSAPublicKeyInfo(PCCERT_CONTEXT pCertContext);
BOOL CryptRSAEncrypt(PCCERT_CONTEXT pCertContext, PVOID Data, DWORD dwDataSize, DWORD dwBuffSize);

BOOL CryptRandomBytes(PUCHAR Data, DWORD dwDataSize);

BOOL CryptMD5Init(HCRYPTPROV *phProv, HCRYPTHASH *phHash);
BOOL CryptMD5Update(HCRYPTHASH hHash, PVOID Data, DWORD dwDataSize);
BOOL CryptMD5Final(HCRYPTHASH hHash, PUCHAR Digest);
void CryptMD5Close(HCRYPTPROV hProv, HCRYPTHASH hHash);

BOOL CryptMD5Digest(PVOID Data, DWORD dwDataSize, PUCHAR Digest);
