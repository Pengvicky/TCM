#ifndef TPM_TO_OHITLS_SYM_H_
#define TPM_TO_OHITLS_SYM_H_

// OpenHITLS-backed symmetric adapter presented under native Ohitls include path
#ifndef SYM_LIB_DEFINED
#define SYM_LIB_DEFINED

#define SYM_LIB_OHITLS

#include <stdint.h>

#include <public/BaseTypes.h>

#include <include/crypto/crypt_errno.h>
#include <crypto/aes/include/crypt_aes.h>
#include <crypto/sm4/include/crypt_sm4.h>

typedef void (*TpmCryptSetSymKeyCall_t)(const unsigned char *in, unsigned char *out, void *keySchedule);
#if ALG_AES
typedef struct
{
    CRYPT_AES_Key key;
} tpmKeyScheduleAES;



#define SWIZZLE(keySchedule, in, out) \
    (const BYTE *)(in), (BYTE *)(out), (void *)(keySchedule)

static inline int32_t OhitlsSetAesEncryptKey(
    const BYTE *key, int keySizeInBits, tpmKeyScheduleAES *schedule)
{
    switch(keySizeInBits)
    {
        case 128:
            return CRYPT_AES_SetEncryptKey128(&schedule->key, (const uint8_t *)key, 16);
        case 192:
            return CRYPT_AES_SetEncryptKey192(&schedule->key, (const uint8_t *)key, 24);
        case 256:
            return CRYPT_AES_SetEncryptKey256(&schedule->key, (const uint8_t *)key, 32);
        default:
            return CRYPT_AES_ERR_KEYLEN;
    }
}

static inline int32_t OhitlsSetAesDecryptKey(
    const BYTE *key, int keySizeInBits, tpmKeyScheduleAES *schedule)
{
    switch(keySizeInBits)
    {
        case 128:
            return CRYPT_AES_SetDecryptKey128(&schedule->key, (const uint8_t *)key, 16);
        case 192:
            return CRYPT_AES_SetDecryptKey192(&schedule->key, (const uint8_t *)key, 24);
        case 256:
            return CRYPT_AES_SetDecryptKey256(&schedule->key, (const uint8_t *)key, 32);
        default:
            return CRYPT_AES_ERR_KEYLEN;
    }
}

static inline void OhitlsAesEncrypt(const BYTE *in, BYTE *out, void *schedule)
{
    tpmKeyScheduleAES *sched = (tpmKeyScheduleAES *)schedule;
    (void)CRYPT_AES_Encrypt(&sched->key, in, out, 16);
}

static inline void OhitlsAesDecrypt(const BYTE *in, BYTE *out, void *schedule)
{
    tpmKeyScheduleAES *sched = (tpmKeyScheduleAES *)schedule;
    (void)CRYPT_AES_Decrypt(&sched->key, in, out, 16);
}

#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule) \
    OhitlsSetAesEncryptKey((key), (keySizeInBits), (tpmKeyScheduleAES *)(schedule))
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule) \
    OhitlsSetAesDecryptKey((key), (keySizeInBits), (tpmKeyScheduleAES *)(schedule))
#define TpmCryptEncryptAES OhitlsAesEncrypt
#define TpmCryptDecryptAES OhitlsAesDecrypt
#endif

#if ALG_SM4
#define SWIZZLE(keySchedule, in, out) \
    (const BYTE *)(in), (BYTE *)(out), (void *)(keySchedule)
typedef struct
{
    CRYPT_SM4_Ctx ctx;
} tpmKeyScheduleSM4;
static inline int32_t OhitlsSetSm4EncryptKey(
    const BYTE *key, int keyBits, tpmKeyScheduleSM4 *schedule)
{
    if(keyBits != 128)
        return CRYPT_SM4_ERR_KEY_LEN;
    return CRYPT_SM4_SetKey(&schedule->ctx, (const uint8_t *)key, 16);
}

static inline int32_t OhitlsSetSm4DecryptKey(
    const BYTE *key, int keyBits, tpmKeyScheduleSM4 *schedule)
{
    if(keyBits != 128)
        return CRYPT_SM4_ERR_KEY_LEN;
    return CRYPT_SM4_SetKey(&schedule->ctx, (const uint8_t *)key, 16);
}

static inline void OhitlsSm4Encrypt(const BYTE *in, BYTE *out, void *schedule)
{
    tpmKeyScheduleSM4 *sched = (tpmKeyScheduleSM4 *)schedule;
    (void)CRYPT_SM4_Encrypt(&sched->ctx, in, out, 16);
}

static inline void OhitlsSm4Decrypt(const BYTE *in, BYTE *out, void *schedule)
{
    tpmKeyScheduleSM4 *sched = (tpmKeyScheduleSM4 *)schedule;
    (void)CRYPT_SM4_Decrypt(&sched->ctx, in, out, 16);
}

#define TpmCryptSetEncryptKeySM4(key, keySizeInBits, schedule) \
    OhitlsSetSm4EncryptKey((key), (keySizeInBits), (tpmKeyScheduleSM4 *)(schedule))
#define TpmCryptSetDecryptKeySM4(key, keySizeInBits, schedule) \
    OhitlsSetSm4DecryptKey((key), (keySizeInBits), (tpmKeyScheduleSM4 *)(schedule))
#define TpmCryptEncryptSM4 OhitlsSm4Encrypt
#define TpmCryptDecryptSM4 OhitlsSm4Decrypt
#endif

#define SymLibSimulationEnd()

#endif /* SYM_LIB_DEFINED */

#endif // TPM_TO_OHITLS_SYM_H_