// Auto-generated style prototypes for OpenHITLS adapter
#ifndef _TPM_TO_OHITLS_SUPPORT_FP_H_
#define _TPM_TO_OHITLS_SUPPORT_FP_H_
#if defined(HASH_LIB_OHITLS) || defined(MATH_LIB_OHITLS) || defined(SYM_LIB_OHITLS)
LIB_EXPORT int TpmBnSupportLibInit(void);
#define BnSupportLibInit TpmBnSupportLibInit
#if CRYPTO_LIB_REPORTING
void OhitlsGetVersion(_CRYPTO_IMPL_DESCRIPTION *result);
#endif
#endif
#endif
