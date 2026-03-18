// FROM part4-code:p1304-p1307

// clang-format off
// clang-format off to preserve define alignment breaking sections.
// this file defines the common optional selections for the TPM library build
// Requires basic YES/NO defines are already set (by TpmBuildSwitches.h)
// Less frequently changed items are in other TpmProfile Headers.
#ifndef _TPM_PROFILE_COMMON_H_
#define _TPM_PROFILE_COMMON_H_
// YES & NO defined by TpmBuildSwitches.h
#if (YES != 1 || NO != 0)
# error YES or NO incorrectly set
#endif
#if defined(ALG_YES) || defined(ALG_NO)
# error ALG_YES and ALG_NO should only be defined by the TpmProfile_Common.h file
#endif
// Change these definitions to turn all algorithms ON or OFF. That is, to turn
// all algorithms on, set ALG_NO to YES. This is intended as a debug feature.
#define ALG_YES YES
#define ALG_NO NO

// Defines according to the processor being built for.
// Are we building for a BIG_ENDIAN processor?
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define BIG_ENDIAN_TPM YES
# else
#  define BIG_ENDIAN_TPM NO
# endif
#elif defined(_WIN32) || defined(__WIN32__) || defined(__LITTLE_ENDIAN__)
# define BIG_ENDIAN_TPM NO
#elif defined(__BIG_ENDIAN__)
# define BIG_ENDIAN_TPM YES
#else
# error Unable to auto-detect endianness; define BIG_ENDIAN_TPM manually for this toolchain.
#endif
#define LITTLE_ENDIAN_TPM !BIG_ENDIAN_TPM
// Does the processor put the most-significant bit at bit position 0?
#define MOST_SIGNIFICANT_BIT_0 NO
#define LEAST_SIGNIFICANT_BIT_0 !MOST_SIGNIFICANT_BIT_0
// Does processor support Auto align?
#define AUTO_ALIGN NO

//***********************************************
// Defines for Symmetric Algorithms
//***********************************************
#define ALG_AES ALG_NO
#define AES_128 (YES * ALG_AES)
#define AES_192 (YES * ALG_AES)
#define AES_256 (YES * ALG_AES)

#define ALG_SM4 ALG_YES
#define SM4_128 (YES * ALG_SM4)

#define ALG_CAMELLIA ALG_NO
#define CAMELLIA_128 (YES * ALG_CAMELLIA)
#define CAMELLIA_192 (YES * ALG_CAMELLIA)
#define CAMELLIA_256 (YES * ALG_CAMELLIA)

#define ALG_TDES ALG_NO
#define TDES_128 (ALG_TDES && YES)
#define TDES_192 (ALG_TDES && YES)

// must be yes if any above are yes.
#define ALG_SYMCIPHER (ALG_AES || ALG_SM4 || ALG_CAMELLIA)
#define ALG_CMAC (YES * ALG_SYMCIPHER)

// block cipher modes
#define ALG_CTR ALG_YES
#define ALG_OFB ALG_NO
#define ALG_CBC ALG_NO
#define ALG_CFB ALG_YES
#define ALG_ECB ALG_NO

//***********************************************
// Defines for RSA Asymmetric Algorithms
//***********************************************
#define ALG_RSA ALG_NO
#define RSA_1024 (YES * ALG_RSA)
#define RSA_2048 (YES * ALG_RSA)
#define RSA_3072 (YES * ALG_RSA)
#define RSA_4096 (NO * ALG_RSA)
#define RSA_16384 (NO * ALG_RSA)
#define ALG_RSASSA (YES * ALG_RSA)
#define ALG_RSAES (YES * ALG_RSA)
#define ALG_RSAPSS (YES * ALG_RSA)
#define ALG_OAEP (YES * ALG_RSA)
// RSA Implementation Styles
// use Chinese Remainder Theorem (5 prime) format for private key ?
#define CRT_FORMAT_RSA NO
#define RSA_DEFAULT_PUBLIC_EXPONENT 0x00010001

//***********************************************
// Defines for ECC Asymmetric Algorithms
//***********************************************
#define ALG_ECC ALG_YES
#define ALG_ECDH (YES * ALG_NO)
#define ALG_ECDSA (YES * ALG_NO)
#define ALG_ECDAA ALG_NO
#define ALG_SM2 (YES * ALG_ECC)
#define ALG_ECSCHNORR (YES * ALG_NO)
#define ALG_KDF1_SP800_56A (YES * ALG_ECC)
#define ALG_ECMQV (YES * ALG_NO)
#define ALG_EDDSA (NO * ALG_NO)
#define ALG_EDDSA_PH (NO * ALG_NO)

#define ECC_NIST_P192 (YES * ALG_NO)
#define ECC_NIST_P224 (YES * ALG_NO)
#define ECC_NIST_P256 (YES * ALG_NO)
#define ECC_NIST_P384 (YES * ALG_NO)
#define ECC_NIST_P521 (YES * ALG_NO)
#define ECC_BN_P256 (YES * ALG_NO)
#define ECC_BN_P638 (YES * ALG_NO)
#define ECC_SM2_P256 (YES * ALG_ECC)

//---------------- TCM2 Curve Enforcement (GB/T 29829-2022) -----------------
#if ECC_SM2_P256 == 0
# error "TCM2 profile requires SM2 P256 curve enabled"
#endif
#if (ECC_NIST_P192 + ECC_NIST_P224 + ECC_NIST_P256 + ECC_NIST_P384 + \
	ECC_NIST_P521 + ECC_BN_P256 + ECC_BN_P638) != 0
# error "Only SM2_P256 curve allowed in TCM2 profile (disable other ECC curves)"
#endif

#define ECC_BP_P256_R1 (NO * ALG_NO)
#define ECC_BP_P384_R1 (NO * ALG_NO)
#define ECC_BP_P512_R1 (NO * ALG_NO)
#define ECC_CURVE_25519 (NO * ALG_NO)
#define ECC_CURVE_448 (NO * ALG_NO)

//***********************************************
// Defines for Hash/XOF Algorithms
//***********************************************
#define ALG_MGF1 ALG_NO
#define ALG_SHA1 ALG_NO
#define ALG_SHA256 ALG_NO
#define ALG_SHA256_192 ALG_NO
#define ALG_SHA384 ALG_NO
#define ALG_SHA512 ALG_NO
#define ALG_SHA3_256 ALG_NO
#define ALG_SHA3_384 ALG_NO
#define ALG_SHA3_512 ALG_NO
#define ALG_SM3_256 ALG_YES
#define ALG_SHAKE256_192 ALG_NO
#define ALG_SHAKE256_256 ALG_NO
#define ALG_SHAKE256_512 ALG_NO

//***********************************************
// Defines for Stateful Signature Algorithms
//***********************************************
#define ALG_LMS ALG_NO
#define ALG_XMSS ALG_NO

//***********************************************
// Defines for Keyed Hashes
//***********************************************
#define ALG_KEYEDHASH ALG_YES
#define ALG_HMAC ALG_YES

//***********************************************
// Defines for KDFs
//***********************************************
#define ALG_KDF2 ALG_YES
#define ALG_KDF1_SP800_108 ALG_YES

//***********************************************
// Defines for Obscuration/MISC/compatibility
//***********************************************
#define ALG_XOR ALG_YES

//***********************************************
// Defines controlling ACT
//***********************************************
#define ACT_SUPPORT NO
#define RH_ACT_0 (NO * ACT_SUPPORT)
#define RH_ACT_1 (NO * ACT_SUPPORT)
#define RH_ACT_2 (NO * ACT_SUPPORT)
#define RH_ACT_3 (NO * ACT_SUPPORT)
#define RH_ACT_4 (NO * ACT_SUPPORT)
#define RH_ACT_5 (NO * ACT_SUPPORT)
#define RH_ACT_6 (NO * ACT_SUPPORT)
#define RH_ACT_7 (NO * ACT_SUPPORT)
#define RH_ACT_8 (NO * ACT_SUPPORT)
#define RH_ACT_9 (NO * ACT_SUPPORT)
#define RH_ACT_A (NO * ACT_SUPPORT)
#define RH_ACT_B (NO * ACT_SUPPORT)
#define RH_ACT_C (NO * ACT_SUPPORT)
#define RH_ACT_D (NO * ACT_SUPPORT)
#define RH_ACT_E (NO * ACT_SUPPORT)
#define RH_ACT_F (NO * ACT_SUPPORT)

#if RH_ACT_0 + RH_ACT_1 + RH_ACT_2 + RH_ACT_3 + RH_ACT_4 + \
	RH_ACT_5 + RH_ACT_6 + RH_ACT_7 + RH_ACT_8 + RH_ACT_9 + \
	RH_ACT_A + RH_ACT_B + RH_ACT_C + RH_ACT_D + RH_ACT_E + \
	RH_ACT_F == 0
# define __ACT_DISABLED
#endif

//***********************************************
// Enable VENDOR_PERMANENT_AUTH_HANDLE?
//***********************************************
#define VENDOR_PERMANENT_AUTH_ENABLED NO
// if YES, this must be valid per Part2 (TPM_RH_AUTH_00 - TPM_RH_AUTH_FF)
// if NO, this must be #undef
#undef VENDOR_PERMANENT_AUTH_HANDLE

//***********************************************
// Defines controlling optional implementation
//***********************************************
#define FIELD_UPGRADE_IMPLEMENTED NO

//***********************************************
// Buffer Sizes based on implementation
//***********************************************
#define MAX_COMMAND_SIZE (4096 - 0x80)
#define MAX_RESPONSE_SIZE (4096 - 0x80)

//***********************************************
// Vendor Info
//***********************************************
// max buffer for vendor commands
#define VENDOR_COMMAND_COUNT 0
#define MAX_VENDOR_BUFFER_SIZE 1024
#define PRIVATE_VENDOR_SPECIFIC_BYTES RSA_PRIVATE_SIZE

//***********************************************
// Defines controlling Firmware- and SVN-limited objects
//***********************************************
#define FW_LIMITED_SUPPORT NO
#define SVN_LIMITED_SUPPORT NO

//***********************************************
// Defines controlling External NV
//***********************************************
#define EXTERNAL_NV NO
#define PERMANENT_NV NO

//---------------- TCM2 Algorithm Enforcement (GB/T 29829-2022) -----------------
#if ALG_RSA != 0
# error "TCM2 profile requires RSA to be disabled (ALG_RSA must be 0)"
#endif
#if ALG_AES != 0
# error "TCM2 profile requires AES to be disabled (ALG_AES must be 0)"
#endif
#if ALG_SHA1 != 0 || ALG_SHA256 != 0 || ALG_SHA384 != 0 || ALG_SHA512 != 0
# error "TCM2 profile requires SHA1/SHA256/SHA384/SHA512 to be disabled"
#endif
#if ALG_SM2 != 1 || ALG_SM3_256 != 1 || ALG_SM4 != 1
# error "TCM2 profile requires SM2, SM3, and SM4 to be enabled"
#endif
#if ALG_ECC != 1
# error "TCM2 profile requires ECC support (for SM2)"
#endif

#endif // _TPM_PROFILE_COMMON_H_