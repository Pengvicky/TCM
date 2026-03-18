// OpenHiTLS specific glue for TPM big-number interface
#ifndef _BN_TO_OHITLS_MATH_H_
#define _BN_TO_OHITLS_MATH_H_

#if !defined(MATH_LIB_TPMBIGNUM) && !defined(_BNOHITLS_H_)
#error This OpenHiTLS interface expects to be used from TpmBigNum
#endif

#include <BnValues.h>
#include <crypto/bn/include/crypt_bn.h>
#include <crypto/ecc/include/crypt_ecc.h>

#if defined(HITLS_SIXTY_FOUR_BITS)
#  if RADIX_BITS != 64
#    error OpenHiTLS big-number radix mismatch (expected 64-bit limbs)
#  endif
#elif defined(HITLS_THIRTY_TWO_BITS)
#  if RADIX_BITS != 32
#    error OpenHiTLS big-number radix mismatch (expected 32-bit limbs)
#  endif
#else
#  error Unsupported OpenHiTLS word size configuration
#endif

typedef struct {
    const TPMBN_ECC_CURVE_CONSTANTS *C; // TPM curve constants view
    ECC_Para *para;                     // OpenHiTLS curve parameters
    BN_Optimizer *opt;                  // Scratch optimizer reused for BN ops
} OHITLS_CURVE_DATA;

typedef OHITLS_CURVE_DATA bigCurveData;

TPM_INLINE const TPMBN_ECC_CURVE_CONSTANTS *AccessCurveConstants(const bigCurveData *E)
{
    return (E != NULL) ? E->C : NULL;
}

#include <Ohitls/support/TpmToOhitlsSupport_fp.h>

#define MathLibSimulationEnd()

#endif // _BN_TO_OHITLS_MATH_H_
