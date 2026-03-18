#ifndef TPM_TO_OHITLS_HASH_H_
#define TPM_TO_OHITLS_HASH_H_

// OpenHITLS-backed hash adapter presented under native Ohitls include path
#ifndef HASH_LIB_DEFINED
#define HASH_LIB_DEFINED

#define HASH_LIB_OHITLS

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <crypto/sha1/include/crypt_sha1.h>
#include <crypto/sha2/include/crypt_sha2.h>
#include <crypto/sm3/include/crypt_sm3.h>

#undef HASH_START_METHOD_DEF
#define HASH_START_METHOD_DEF void(HASH_START_METHOD)(void *state)
#undef HASH_DATA_METHOD_DEF
#define HASH_DATA_METHOD_DEF void(HASH_DATA_METHOD)(void *state, const BYTE *buffer, size_t size)
#undef HASH_END_METHOD_DEF
#define HASH_END_METHOD_DEF void(HASH_END_METHOD)(BYTE *buffer, void *state)
#undef HASH_STATE_COPY_METHOD_DEF
#define HASH_STATE_COPY_METHOD_DEF void(HASH_STATE_COPY_METHOD)(void *to, const void *from, size_t size)
#undef HASH_STATE_EXPORT_METHOD_DEF
#define HASH_STATE_EXPORT_METHOD_DEF void(HASH_STATE_EXPORT_METHOD)(BYTE *to, const void *from, size_t size)
#undef HASH_STATE_IMPORT_METHOD_DEF
#define HASH_STATE_IMPORT_METHOD_DEF void(HASH_STATE_IMPORT_METHOD)(void *to, const BYTE *from, size_t size)

typedef struct
{
    uint8_t m[CRYPT_SHA1_BLOCKSIZE];
    uint32_t h[CRYPT_SHA1_DIGESTSIZE / sizeof(uint32_t)];
    uint32_t hNum;
    uint32_t lNum;
    int32_t errorCode;
    uint32_t count;
} tpmHashStateSHA1_t;

typedef struct
{
    uint32_t h[CRYPT_SHA2_256_DIGESTSIZE / sizeof(uint32_t)];
    uint32_t block[CRYPT_SHA2_256_BLOCKSIZE / sizeof(uint32_t)];
    uint32_t lNum;
    uint32_t hNum;
    uint32_t blocklen;
    uint32_t outlen;
    uint32_t errorCode;
} tpmHashStateSHA256_t;

typedef struct
{
    uint64_t h[CRYPT_SHA2_512_DIGESTSIZE / sizeof(uint64_t)];
    uint8_t block[CRYPT_SHA2_512_BLOCKSIZE];
    uint64_t lNum;
    uint64_t hNum;
    uint32_t num;
    uint32_t mdlen;
    uint32_t errorCode;
} tpmHashStateSHA512_t;

typedef tpmHashStateSHA512_t tpmHashStateSHA384_t;

typedef struct
{
    uint32_t h[CRYPT_SM3_DIGESTSIZE / sizeof(uint32_t)];
    uint32_t hNum;
    uint32_t lNum;
    uint8_t block[CRYPT_SM3_BLOCKSIZE];
    uint32_t num;
} tpmHashStateSM3_256_t;

static inline CRYPT_SHA1_Ctx *OhitlsSha1Ctx(void *state)
{
    return (CRYPT_SHA1_Ctx *)state;
}

static inline CRYPT_SHA2_256_Ctx *OhitlsSha256Ctx(void *state)
{
    return (CRYPT_SHA2_256_Ctx *)state;
}

static inline CRYPT_SHA2_384_Ctx *OhitlsSha384Ctx(void *state)
{
    return (CRYPT_SHA2_384_Ctx *)state;
}

static inline CRYPT_SHA2_512_Ctx *OhitlsSha512Ctx(void *state)
{
    return (CRYPT_SHA2_512_Ctx *)state;
}

static inline CRYPT_SM3_Ctx *OhitlsSm3Ctx(void *state)
{
    return (CRYPT_SM3_Ctx *)state;
}

#if ALG_SHA1
static inline void OhitlsHashStartSHA1(void *state)
{
    (void)CRYPT_SHA1_Init(OhitlsSha1Ctx(state), NULL);
}

static inline void OhitlsHashDataSHA1(void *state, const BYTE *buffer, size_t size)
{
    (void)CRYPT_SHA1_Update(OhitlsSha1Ctx(state), buffer, (uint32_t)size);
}

static inline void OhitlsHashEndSHA1(BYTE *buffer, void *state)
{
    uint32_t outLen = CRYPT_SHA1_DIGESTSIZE;
    (void)CRYPT_SHA1_Final(OhitlsSha1Ctx(state), buffer, &outLen);
}

static inline void OhitlsHashCopySHA1(void *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA1_t));
}

static inline uint16_t OhitlsHashGetDigestSizeSHA1(void)
{
    return CRYPT_SHA1_DIGESTSIZE;
}

static inline uint16_t OhitlsHashGetBlockSizeSHA1(void)
{
    return CRYPT_SHA1_BLOCKSIZE;
}

static inline void OhitlsHashStateExportSHA1(BYTE *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA1_t));
}

static inline void OhitlsHashStateImportSHA1(void *to, const BYTE *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA1_t));
}

#define tpmHashStart_SHA1 OhitlsHashStartSHA1
#define tpmHashData_SHA1 OhitlsHashDataSHA1
#define tpmHashEnd_SHA1 OhitlsHashEndSHA1
#define tpmHashStateCopy_SHA1 OhitlsHashCopySHA1
#define tpmHashStateExport_SHA1 OhitlsHashStateExportSHA1
#define tpmHashStateImport_SHA1 OhitlsHashStateImportSHA1
#endif

#if ALG_SHA256
static inline void OhitlsHashStartSHA256(void *state)
{
    (void)CRYPT_SHA2_256_Init(OhitlsSha256Ctx(state), NULL);
}

static inline void OhitlsHashDataSHA256(void *state, const BYTE *buffer, size_t size)
{
    (void)CRYPT_SHA2_256_Update(OhitlsSha256Ctx(state), buffer, (uint32_t)size);
}

static inline void OhitlsHashEndSHA256(BYTE *buffer, void *state)
{
    uint32_t outLen = CRYPT_SHA2_256_DIGESTSIZE;
    (void)CRYPT_SHA2_256_Final(OhitlsSha256Ctx(state), buffer, &outLen);
}

static inline void OhitlsHashCopySHA256(void *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA256_t));
}

static inline uint16_t OhitlsHashGetDigestSizeSHA256(void)
{
    return CRYPT_SHA2_256_DIGESTSIZE;
}

static inline uint16_t OhitlsHashGetBlockSizeSHA256(void)
{
    return CRYPT_SHA2_256_BLOCKSIZE;
}

static inline void OhitlsHashStateExportSHA256(BYTE *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA256_t));
}

static inline void OhitlsHashStateImportSHA256(void *to, const BYTE *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA256_t));
}

#define tpmHashStart_SHA256 OhitlsHashStartSHA256
#define tpmHashData_SHA256 OhitlsHashDataSHA256
#define tpmHashEnd_SHA256 OhitlsHashEndSHA256
#define tpmHashStateCopy_SHA256 OhitlsHashCopySHA256
#define tpmHashStateExport_SHA256 OhitlsHashStateExportSHA256
#define tpmHashStateImport_SHA256 OhitlsHashStateImportSHA256
#endif

#if ALG_SHA384
static inline void OhitlsHashStartSHA384(void *state)
{
    (void)CRYPT_SHA2_384_Init(OhitlsSha384Ctx(state), NULL);
}

static inline void OhitlsHashDataSHA384(void *state, const BYTE *buffer, size_t size)
{
    (void)CRYPT_SHA2_384_Update(OhitlsSha384Ctx(state), buffer, (uint32_t)size);
}

static inline void OhitlsHashEndSHA384(BYTE *buffer, void *state)
{
    uint32_t outLen = CRYPT_SHA2_384_DIGESTSIZE;
    (void)CRYPT_SHA2_384_Final(OhitlsSha384Ctx(state), buffer, &outLen);
}

static inline void OhitlsHashCopySHA384(void *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA384_t));
}

static inline uint16_t OhitlsHashGetDigestSizeSHA384(void)
{
    return CRYPT_SHA2_384_DIGESTSIZE;
}

static inline uint16_t OhitlsHashGetBlockSizeSHA384(void)
{
    return CRYPT_SHA2_384_BLOCKSIZE;
}

static inline void OhitlsHashStateExportSHA384(BYTE *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA384_t));
}

static inline void OhitlsHashStateImportSHA384(void *to, const BYTE *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA384_t));
}

#define tpmHashStart_SHA384 OhitlsHashStartSHA384
#define tpmHashData_SHA384 OhitlsHashDataSHA384
#define tpmHashEnd_SHA384 OhitlsHashEndSHA384
#define tpmHashStateCopy_SHA384 OhitlsHashCopySHA384
#define tpmHashStateExport_SHA384 OhitlsHashStateExportSHA384
#define tpmHashStateImport_SHA384 OhitlsHashStateImportSHA384
#endif

#if ALG_SHA512
static inline void OhitlsHashStartSHA512(void *state)
{
    (void)CRYPT_SHA2_512_Init(OhitlsSha512Ctx(state), NULL);
}

static inline void OhitlsHashDataSHA512(void *state, const BYTE *buffer, size_t size)
{
    (void)CRYPT_SHA2_512_Update(OhitlsSha512Ctx(state), buffer, (uint32_t)size);
}

static inline void OhitlsHashEndSHA512(BYTE *buffer, void *state)
{
    uint32_t outLen = CRYPT_SHA2_512_DIGESTSIZE;
    (void)CRYPT_SHA2_512_Final(OhitlsSha512Ctx(state), buffer, &outLen);
}

static inline void OhitlsHashCopySHA512(void *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA512_t));
}

static inline uint16_t OhitlsHashGetDigestSizeSHA512(void)
{
    return CRYPT_SHA2_512_DIGESTSIZE;
}

static inline uint16_t OhitlsHashGetBlockSizeSHA512(void)
{
    return CRYPT_SHA2_512_BLOCKSIZE;
}

static inline void OhitlsHashStateExportSHA512(BYTE *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA512_t));
}

static inline void OhitlsHashStateImportSHA512(void *to, const BYTE *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSHA512_t));
}

#define tpmHashStart_SHA512 OhitlsHashStartSHA512
#define tpmHashData_SHA512 OhitlsHashDataSHA512
#define tpmHashEnd_SHA512 OhitlsHashEndSHA512
#define tpmHashStateCopy_SHA512 OhitlsHashCopySHA512
#define tpmHashStateExport_SHA512 OhitlsHashStateExportSHA512
#define tpmHashStateImport_SHA512 OhitlsHashStateImportSHA512
#endif

#if ALG_SM3_256
static inline void OhitlsHashStartSM3_256(void *state)
{
    (void)CRYPT_SM3_Init(OhitlsSm3Ctx(state), NULL);
}

static inline void OhitlsHashDataSM3_256(void *state, const BYTE *buffer, size_t size)
{
    (void)CRYPT_SM3_Update(OhitlsSm3Ctx(state), buffer, (uint32_t)size);
}

static inline void OhitlsHashEndSM3_256(BYTE *buffer, void *state)
{
    uint32_t outLen = CRYPT_SM3_DIGESTSIZE;
    (void)CRYPT_SM3_Final(OhitlsSm3Ctx(state), buffer, &outLen);
}

static inline void OhitlsHashCopySM3_256(void *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSM3_256_t));
}

static inline uint16_t OhitlsHashGetDigestSizeSM3_256(void)
{
    return CRYPT_SM3_DIGESTSIZE;
}

static inline uint16_t OhitlsHashGetBlockSizeSM3_256(void)
{
    return CRYPT_SM3_BLOCKSIZE;
}

static inline void OhitlsHashStateExportSM3_256(BYTE *to, const void *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSM3_256_t));
}

static inline void OhitlsHashStateImportSM3_256(void *to, const BYTE *from, size_t size)
{
    (void)size;
    (void)memcpy(to, from, sizeof(tpmHashStateSM3_256_t));
}

#define tpmHashStart_SM3_256 OhitlsHashStartSM3_256
#define tpmHashData_SM3_256 OhitlsHashDataSM3_256
#define tpmHashEnd_SM3_256 OhitlsHashEndSM3_256
#define tpmHashStateCopy_SM3_256 OhitlsHashCopySM3_256
#define tpmHashStateExport_SM3_256 OhitlsHashStateExportSM3_256
#define tpmHashStateImport_SM3_256 OhitlsHashStateImportSM3_256
#endif

#ifdef _CRYPT_HASH_C_
typedef BYTE *PBYTE;
typedef const BYTE *PCBYTE;

#define HASH_START(hashState) \
    ((hashState)->def->method.start)((void *)&(hashState)->state)
#define HASH_DATA(hashState, dInSize, dIn) \
    ((hashState)->def->method.data)((void *)&(hashState)->state, dIn, dInSize)
#define HASH_END(hashState, buffer) \
    ((hashState)->def->method.end)(buffer, (void *)&(hashState)->state)
#define HASH_STATE_COPY(hashStateOut, hashStateIn)                                 \
    ((hashStateIn)->def->method.copy)((void *)&(hashStateOut)->state,              \
                                      (const void *)&(hashStateIn)->state,        \
                                      (hashStateIn)->def->contextSize)
#define HASH_STATE_EXPORT(to, hashStateFrom)                                       \
    ((hashStateFrom)->def->method.copyOut)(                                        \
        &(((BYTE *)(to))[offsetof(HASH_STATE, state)]),                            \
        (const void *)&(hashStateFrom)->state,                                     \
        (hashStateFrom)->def->contextSize)
#define HASH_STATE_IMPORT(hashStateTo, from)                                       \
    ((hashStateTo)->def->method.copyIn)(                                           \
        (void *)&(hashStateTo)->state,                                             \
        &(((const BYTE *)(from))[offsetof(HASH_STATE, state)]),                    \
        (hashStateTo)->def->contextSize)
#endif

#if ALG_SHA1
#define SYM_LIB_HASH_DISPATCH_CASE_SHA1(ALG) \
    case ALG_SHA1:                        \
        (ALG) = CRYPT_SHA1_DIGESTSIZE;    \
        break
#else
#define SYM_LIB_HASH_DISPATCH_CASE_SHA1(ALG)
#endif

#if ALG_SHA256
#define SYM_LIB_HASH_DISPATCH_CASE_SHA256(ALG) \
    case ALG_SHA256:                          \
        (ALG) = CRYPT_SHA2_256_DIGESTSIZE;    \
        break
#else
#define SYM_LIB_HASH_DISPATCH_CASE_SHA256(ALG)
#endif

#if ALG_SHA384
#define SYM_LIB_HASH_DISPATCH_CASE_SHA384(ALG) \
    case ALG_SHA384:                          \
        (ALG) = CRYPT_SHA2_384_DIGESTSIZE;    \
        break
#else
#define SYM_LIB_HASH_DISPATCH_CASE_SHA384(ALG)
#endif

#if ALG_SHA512
#define SYM_LIB_HASH_DISPATCH_CASE_SHA512(ALG) \
    case ALG_SHA512:                          \
        (ALG) = CRYPT_SHA2_512_DIGESTSIZE;    \
        break
#else
#define SYM_LIB_HASH_DISPATCH_CASE_SHA512(ALG)
#endif

#if ALG_SM3_256
#define SYM_LIB_HASH_DISPATCH_CASE_SM3(ALG) \
    case ALG_SM3_256:                     \
        (ALG) = CRYPT_SM3_DIGESTSIZE;     \
        break
#else
#define SYM_LIB_HASH_DISPATCH_CASE_SM3(ALG)
#endif

#define HASH_START_METHOD(alg) OhitlsHashStart##alg
#define HASH_DATA_METHOD(alg) OhitlsHashData##alg
#define HASH_END_METHOD(alg) OhitlsHashEnd##alg
#define HASH_STATE_STRUCT(alg) tpmHashState##alg##_t
#define HASH_STATE_COPY_METHOD(alg) OhitlsHashCopy##alg
#define HASH_STATE_EXPORT_METHOD(alg) OhitlsHashStateExport##alg
#define HASH_STATE_IMPORT_METHOD(alg) OhitlsHashStateImport##alg
#define HASH_GET_DIGEST_SIZE(alg) OhitlsHashGetDigestSize##alg
#define HASH_GET_BLOCK_SIZE(alg) OhitlsHashGetBlockSize##alg

#define LibHashInit()
#define HashLibSimulationEnd()

#define GetDigestSizeFromState(state, result)            \
    switch((state)->type)                                \
    {                                                    \
        SYM_LIB_HASH_DISPATCH_CASE_SHA1(result);         \
        SYM_LIB_HASH_DISPATCH_CASE_SHA256(result);       \
        SYM_LIB_HASH_DISPATCH_CASE_SHA384(result);       \
        SYM_LIB_HASH_DISPATCH_CASE_SHA512(result);       \
        SYM_LIB_HASH_DISPATCH_CASE_SM3(result);          \
        default:                                         \
            (result) = 0;                                \
            break;                                       \
    }

#endif /* HASH_LIB_DEFINED */

#endif // TPM_TO_OHITLS_HASH_H_