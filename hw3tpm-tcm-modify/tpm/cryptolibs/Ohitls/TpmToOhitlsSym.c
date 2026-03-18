#include <Ohitls/TpmToOhitlsSym.h>

#if ALG_SM4
/*
 * Some TPM components expect legacy OpenSSL-style CRYPT_SM4_SetEncryptKey/
 * DecryptKey entry points. OpenHiTLS exposes a consolidated CRYPT_SM4_SetKey
 * API, so provide thin wrappers here to keep the TPM build self-contained.
 */
int32_t CRYPT_SM4_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    return CRYPT_SM4_SetKey(ctx, key, len);
}

int32_t CRYPT_SM4_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len)
{
    return CRYPT_SM4_SetKey(ctx, key, len);
}
#endif
