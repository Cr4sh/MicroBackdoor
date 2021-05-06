#include "stdafx.h"
//--------------------------------------------------------------------------------------
BOOL CertDigest(PCCERT_CONTEXT pCertContext, char *lpszDigest)
{
    UCHAR Sum[SHA1_SUM_SIZE];
    DWORD SumLen = sizeof(Sum);

    ZeroMemory(Sum, sizeof(Sum));
    ZeroMemory(lpszDigest, CERTIFICATE_DIGEST_SIZE_STR);

    // calculate SHA1 hash from the client ceritifcate contents
    if (CryptHashCertificate(0, CALG_SHA1, 0, 
        pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, Sum, &SumLen))
    {
        // convert hash sum to the hexadecimal string
        for (int i = 0; i < sizeof(Sum); i += 1)
        {
            wsprintf(lpszDigest + i * 2, "%.2X", Sum[i]);
        }

        return TRUE;
    }
    else
    {
        DbgMsg("CryptHashCertificate() ERROR 0x%.8x\n", GetLastError());
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL CertLoad(PVOID Data, DWORD dwDataSize, PCCERT_CONTEXT *pRetCertContext)
{
    if (pRetCertContext)
    {
        *pRetCertContext = NULL;
    }

    CERT_BLOB CertData;
    CertData.cbData = dwDataSize;
    CertData.pbData = (BYTE *)Data;

    PCCERT_CONTEXT pCertContext = NULL;

    // query CERT_CONTEXT from the PEM certificate data
    if (CryptQueryObject(
        CERT_QUERY_OBJECT_BLOB, &CertData,
        CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_ALL,
        0, NULL, NULL, NULL, NULL, NULL,
        (const void **)&pCertContext) != 0)
    {
        if (pCertContext)
        {
            DWORD dwTypeParam = 0;
            WCHAR szCertName[MAX_PATH], szIssuer[MAX_PATH], szSubject[MAX_PATH];

            wcscpy(szCertName, L"<unnamed>");
            wcscpy(szIssuer, L"<unknown>");
            wcscpy(szSubject, L"<unknown>");

            // query certificate name
            CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 
                               0, &dwTypeParam, szCertName, MAX_PATH);

            // decode certificate issuer string
            CertNameToStrW(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, 0, szIssuer, MAX_PATH);

            // decode certificate subject string
            CertNameToStrW(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, 0, szSubject, MAX_PATH);
            
            char szDigest[CERTIFICATE_DIGEST_SIZE_STR];

            // calculate certificate digest
            if (CertDigest(pCertContext, szDigest))
            {
                DbgMsg(
                    __FUNCTION__"(): Name = \"%ws\", issuer = \"%ws\", subject = \"%ws\"\n",
                    szCertName, szIssuer, szSubject
                );

                DbgMsg(__FUNCTION__"(): Digest = %s\n", szDigest);

                if (pRetCertContext)
                {
                    // return certificate information
                    *pRetCertContext = pCertContext;
                }
                else
                {
                    // just check for valid certificate data
                    CertFreeCertificateContext(pCertContext);
                }

                return TRUE;
            }

            CertFreeCertificateContext(pCertContext);
        }
    }
    else
    {
        DbgMsg("CryptQueryObject() ERROR 0x%.8x\n", GetLastError());
    }

    return FALSE;
}
//--------------------------------------------------------------------------------------
DWORD CryptRSAPublicKeyInfo(PCCERT_CONTEXT pCertContext)
{
    DWORD dwRet = 0;
    
    DbgMsg(
        __FUNCTION__"(): Algorithm ID = \"%s\"\n",
        pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId
    );

    if (lstrcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA))
    {
        DbgMsg(__FUNCTION__"() ERROR: Unsupported algorithm\n");
        return FALSE;
    }

    BOOL bSuccess = FALSE;
    HCRYPTPROV hTempProv = NULL;    

    // create temporary key container
    if (!(bSuccess = CryptAcquireContext(&hTempProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET)))
    {
        // try to open existing container
        bSuccess = CryptAcquireContext(&hTempProv, NULL, NULL, PROV_RSA_AES, 0);
    }

    if (bSuccess)
    {
        HCRYPTKEY hTempKey = NULL;

        // import public key to get key handle
        if (CryptImportPublicKeyInfo(
            hTempProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &pCertContext->pCertInfo->SubjectPublicKeyInfo, &hTempKey))
        {
            DWORD dwKeyDataSize = 0;
            PBYTE KeyData = NULL;

            // get public key size
            if (CryptExportKey(hTempKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwKeyDataSize))
            {
                // allocate a buffer for the public key
                if (KeyData = (PBYTE)M_ALLOC(dwKeyDataSize))
                {
                    if (CryptExportKey(hTempKey, NULL, PUBLICKEYBLOB, 0, KeyData, &dwKeyDataSize))
                    {
                        // get RSA public key headers
                        BLOBHEADER *pKeyHdr = (BLOBHEADER *)KeyData;
                        RSAPUBKEY *pRsaPubKey = (RSAPUBKEY *)(pKeyHdr + 1);

                        if (pKeyHdr->bType != PUBLICKEYBLOB)
                        {
                            DbgMsg(__FUNCTION__"() ERROR: Bad blob type\n");
                            goto _end;
                        }

                        // check for RSA key exchange algorithm
                        if (pKeyHdr->aiKeyAlg != CALG_RSA_KEYX)
                        {
                            DbgMsg(__FUNCTION__"() ERROR: Unsupported algorithm\n");
                            goto _end;
                        }

                        DbgMsg(
                            __FUNCTION__"(): Bits = %d, exponent = %d\n",
                            pRsaPubKey->bitlen, pRsaPubKey->pubexp
                        );

                        // check for public key blob
                        if (pRsaPubKey->magic != RSA_MAGIC_PUB)
                        {
                            DbgMsg(__FUNCTION__"() ERROR: Not a public key\n");
                            goto _end;
                        }

                        return pRsaPubKey->bitlen / 8;                        
                    }
                    else
                    {
                        DbgMsg("CryptExportKey() ERROR 0x%.8x\n", GetLastError());
                    }
_end:
                    M_FREE(KeyData);
                }
                else
                {
                    DbgMsg("M_ALLOC() ERROR 0x%.8x\n", GetLastError());
                }
            }
            else
            {
                DbgMsg("CryptExportKey() ERROR 0x%.8x\n", GetLastError());
            }

            CryptDestroyKey(hTempKey);
        }
        else
        {
            DbgMsg("CryptImportPublicKeyInfo() ERROR 0x%.8x\n", GetLastError());
        }

        CryptReleaseContext(hTempProv, 0);
    }
    else
    {
        DbgMsg("CryptAcquireContext() ERROR 0x%.8x\n", GetLastError());
    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
BOOL CryptRSAEncrypt(PCCERT_CONTEXT pCertContext, PVOID Data, DWORD dwDataSize, DWORD dwBuffSize)
{
    HCRYPTPROV hTempProv = NULL;
    BOOL bRet = FALSE, bSuccess = FALSE;

    if (lstrcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA))
    {
        DbgMsg(__FUNCTION__"() ERROR: Unsupported algorithm\n");
        return FALSE;
    }

    // create temporary key container
    if (!(bSuccess = CryptAcquireContext(&hTempProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET)))
    {
        // try to open existing container
        bSuccess = CryptAcquireContext(&hTempProv, NULL, NULL, PROV_RSA_AES, 0);
    }

    if (bSuccess)
    {
        HCRYPTKEY hTempKey = NULL;

        // import public key to get key handle
        if (CryptImportPublicKeyInfo(
            hTempProv, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            &pCertContext->pCertInfo->SubjectPublicKeyInfo, &hTempKey))
        {
            // allocate tempporary buffer
            PUCHAR Temp = (PUCHAR)M_ALLOC(dwBuffSize);
            if (Temp)
            {
                memcpy(Temp, Data, dwDataSize);

                if (bRet = CryptEncrypt(hTempKey, NULL, TRUE, 0, (BYTE *)Temp, &dwDataSize, dwBuffSize))
                {
                    for (DWORD i = 0; i < dwDataSize; i += 1)
                    {
                        // convert RSA data from little endian to big endian
                        *((PUCHAR)Data + i) = Temp[dwDataSize - 1 - i];
                    }
                }
                else
                {
                    DbgMsg("CryptEncrypt() ERROR 0x%.8x\n", GetLastError());
                }

                M_FREE(Temp);
            }
            else
            {
                DbgMsg("M_ALLOC() ERROR 0x%.8x\n", GetLastError());
            }

            CryptDestroyKey(hTempKey);
        }
        else
        {
            DbgMsg("CryptImportPublicKeyInfo() ERROR 0x%.8x\n", GetLastError());
        }

        CryptReleaseContext(hTempProv, 0);
    }
    else
    {
        DbgMsg("CryptAcquireContext() ERROR 0x%.8x\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL CryptRandomBytes(PUCHAR Data, DWORD dwDataSize)
{
    BOOL bSuccess = FALSE;
    HCRYPTPROV hProvider = NULL;

    if (!(bSuccess = CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, 0)))
    {
        if (GetLastError() == NTE_BAD_KEYSET)
        {
            bSuccess = CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        }
    }

    if (bSuccess)
    {
        // generate random numbers using windows crypto API
        if (!(bSuccess = CryptGenRandom(hProvider, dwDataSize, Data)))
        {
            DbgMsg("CryptGenRandom() ERROR 0x%.8x\n", GetLastError());
        }

        CryptReleaseContext(hProvider, 0);
    }
    else
    {
        DbgMsg("CryptAcquireContext() ERROR 0x%.8x\n", GetLastError());
    }

    return bSuccess;
}
//--------------------------------------------------------------------------------------
BOOL CryptMD5Init(HCRYPTPROV *phProv, HCRYPTHASH *phHash)
{
    BOOL bRet = FALSE;
     
    // Get handle to the crypto provider
    if (CryptAcquireContext(phProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        if (CryptCreateHash(*phProv, CALG_MD5, 0, 0, phHash))
        {
            return TRUE;
        }
        else
        {
            DbgMsg("CryptCreateHash() ERROR 0x%.8x\n", GetLastError());
        }

        CryptReleaseContext(*phProv, 0);
    }
    else
    {
        DbgMsg("CryptAcquireContext() ERROR 0x%.8x\n", GetLastError());
    }

    *phProv = NULL;
    *phHash = NULL;

    return FALSE;
}
//--------------------------------------------------------------------------------------
BOOL CryptMD5Update(HCRYPTHASH hHash, PVOID Data, DWORD dwDataSize)
{
    return CryptHashData(hHash, (const BYTE *)Data, dwDataSize, 0);
}
//--------------------------------------------------------------------------------------
BOOL CryptMD5Final(HCRYPTHASH hHash, PUCHAR Digest)
{
    DWORD dwDigestLen = MD5_SUM_SIZE;
    ZeroMemory(Digest, dwDigestLen);

    return CryptGetHashParam(hHash, HP_HASHVAL, Digest, &dwDigestLen, 0);    
}
//--------------------------------------------------------------------------------------
void CryptMD5Close(HCRYPTPROV hProv, HCRYPTHASH hHash)
{
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}
//--------------------------------------------------------------------------------------
BOOL CryptMD5Digest(PVOID Data, DWORD dwDataSize, PUCHAR Digest)
{
    BOOL bRet = FALSE;
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    if (CryptMD5Init(&hProv, &hHash))
    {
        if (CryptMD5Update(hHash, Data, dwDataSize))
        {
            bRet = CryptMD5Final(hHash, Digest);
        }

        CryptMD5Close(hProv, hHash);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
// EoF
