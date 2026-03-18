// OpenHiTLS big-number adapter umbrella header
#ifndef _BNOHITLS_H_
#define _BNOHITLS_H_

#include <public/tpm_public.h>
#include <public/prototypes/TpmFail_fp.h>

#define MATH_LIB_OHITLS

#include <Ohitls/BnToOhitlsMath.h>

#include <BnSupport_Interface.h>
#include <BnUtil_fp.h>
#include <BnMemory_fp.h>
#include <BnMath_fp.h>
#include <BnConvert_fp.h>

#if CRYPTO_LIB_REPORTING
#include <CryptoInterface.h>
void OhitlsGetVersion(_CRYPTO_IMPL_DESCRIPTION *result);
#endif

#endif // _BNOHITLS_H_
