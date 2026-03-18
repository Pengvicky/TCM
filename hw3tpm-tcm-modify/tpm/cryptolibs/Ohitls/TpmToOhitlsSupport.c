#include <stdio.h>
#include <CryptoInterface.h>
#include <Ohitls/TpmToOsslSupport_fp.h>

LIB_EXPORT int TpmBnSupportLibInit(void)
{
    return TRUE;
}

#if defined(BnSupportLibInit)
#undef BnSupportLibInit
#define LOCAL_BN_SUPPORT_ALIAS 1
#endif

/* Maintain the legacy entry point expected by existing TPM code paths. */
LIB_EXPORT int BnSupportLibInit(void)
{
    return TpmBnSupportLibInit();
}

#if CRYPTO_LIB_REPORTING
void OhitlsGetVersion(_CRYPTO_IMPL_DESCRIPTION *result)
{
    snprintf(result->name, sizeof(result->name), "OpenHITLS");
    snprintf(result->version, sizeof(result->version), "EAL");
}
#endif

#ifdef LOCAL_BN_SUPPORT_ALIAS
#undef LOCAL_BN_SUPPORT_ALIAS
#define BnSupportLibInit TpmBnSupportLibInit
#endif
