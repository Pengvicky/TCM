// FROM part4-code:p915-p917

#include "Tpm.h"
#include "TpmEcc_Signature_ECDAA_fp.h"
#include "TpmEcc_Signature_Util_fp.h"
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"

#if ALG_ECC && ALG_ECDAA

//*** TpmEcc_SignEcdaa()
//
// This function performs 's' = 'r' + 'T' * 'd' mod 'q' where
// 1) 'r' is a random, or pseudo-random value created in the commit phase
// 2) 'nonceK' is a TPM-generated, random value 0 < 'nonceK' < 'n'
// 3) 'T' is mod 'q' of "Hash"('nonceK' || 'digest'), and
// 4) 'd' is a private key.
//
// The signature is the tuple ('nonceK', 's')
//
// Regrettably, the parameters in this function kind of collide with the parameter
// names used in ECSCHNORR making for a lot of confusion.
//  Return Type: TPM_RC
//      TPM_RC_SCHEME       unsupported hash algorithm
//      TPM_RC_NO_RESULT    cannot get values from random number generator
TPM_RC TpmEcc_SignEcdaa(
    TPM2B_ECC_PARAMETER*  nonceK,  // OUT: 'nonce' component of the signature
    Crypt_Int*            bnS,     // OUT: 's' component of the signature
    const Crypt_EccCurve* E,       // IN: the curve used in signing
    Crypt_Int*            bnD,     // IN: the private key
    const TPM2B_DIGEST*   digest,  // IN: the value to sign (mod 'q')
    TPMT_ECC_SCHEME*      scheme,  // IN: signing scheme (contains the
                                   //      commit count value).
    OBJECT*     eccKey,            // IN: The signing key
    RAND_STATE* rand               // IN: a random number state
)
{
    TPM_RC              retVal;
    TPM2B_ECC_PARAMETER r;
    HASH_STATE          state;
    TPM2B_DIGEST        T;
    CRYPT_INT_MAX(bnT);
    //
    NOT_REFERENCED(rand);
    if(!CryptGenerateR(&r,
                       &scheme->details.ecdaa.count,
                       eccKey->publicArea.parameters.eccDetail.curveID,
                       &eccKey->name))
        retVal = TPM_RC_VALUE;
    else
    {
        // This allocation is here because 'r' doesn't have a value until
        // CrypGenerateR() is done.
        CRYPT_ECC_INITIALIZED(bnR, &r);
        do
        {
            // generate nonceK such that 0 < nonceK < n
            // use bnT as a temp.
            if(!TpmEcc_GenPrivateScalar(bnT, E, rand))
            {
                retVal = TPM_RC_NO_RESULT;
                break;
            }
            TpmMath_IntTo2B(bnT, &nonceK->b, 0);

            T.t.size = CryptHashStart(&state, scheme->details.ecdaa.hashAlg);
            if(T.t.size == 0)
            {
                retVal = TPM_RC_SCHEME;
            }
            else
            {
                CryptDigestUpdate2B(&state, &nonceK->b);
                CryptDigestUpdate2B(&state, &digest->b);
                CryptHashEnd2B(&state, &T.b);
                TpmMath_IntFrom2B(bnT, &T.b);
                // Watch out for the name collisions in this call!!
                retVal = TpmEcc_SchnorrCalculateS(
                    bnS,
                    bnR,
                    bnT,
                    bnD,
                    ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E)));
            }
        } while(retVal == TPM_RC_NO_RESULT);
        // Because the rule is that internal state is not modified if the command
        // fails, only end the commit if the command succeeds.
        // NOTE that if the result of the Schnorr computation was zero
        // it will probably not be worthwhile to run the same command again because
        // the result will still be zero. This means that the Commit command will
        // need to be run again to get a new commit value for the signature.
        if(retVal == TPM_RC_SUCCESS)
            CryptEndCommit(scheme->details.ecdaa.count);
    }
    return retVal;
}

//*** TpmEcc_ValidateSignatureEcdaa()
// Validate the ECDAA signature by checking that [s]G == [nonceK]G + [T]Q.
TPM_RC TpmEcc_ValidateSignatureEcdaa(
    const TPM2B_ECC_PARAMETER* nonceK,  // IN: 'nonce' component of the signature
    const Crypt_Int*           bnS,     // IN: 's' component of the signature
    TPM_ALG_ID                 hashAlg, // IN: hash algorithm of the signature
    const Crypt_EccCurve*      E,       // IN: the curve used in the signature
    const Crypt_Point*         ecQ,     // IN: public point of the key
    const TPM2B_DIGEST*        digest   // IN: digest that was signed
)
{
    TPM_RC                 retVal = TPM_RC_SIGNATURE;
    const Crypt_Int*       order;
    UINT16                 digestSize;
    HASH_STATE             hashState;
    TPM2B_TYPE(T, MAX(MAX_DIGEST_SIZE, MAX_ECC_PARAMETER_BYTES));
    TPM2B_T                hashBuf;
    TPM2B*                 hash2B = &hashBuf.b;
    CRYPT_INT_MAX(bnK);
    CRYPT_INT_MAX(bnT);
    CRYPT_INT_MAX(bnNegT);
    CRYPT_POINT_VAR(pointCheck);
    CRYPT_POINT_VAR(pointK);
    TPMS_ECC_POINT         lhs;
    TPMS_ECC_POINT         rhs;

    MemorySet(&lhs, 0, sizeof(lhs));
    MemorySet(&rhs, 0, sizeof(rhs));

    if(nonceK == NULL || digest == NULL || E == NULL || ecQ == NULL)
        return TPM_RC_SIGNATURE;

    digestSize = CryptHashGetDigestSize(hashAlg);
    if(digestSize == 0)
        return TPM_RC_SIGNATURE;

    order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));

    TpmMath_IntFrom2B(bnK, &nonceK->b);
    if(ExtMath_IsZero(bnK) || (ExtMath_UnsignedCmp(bnK, order) >= 0))
        return TPM_RC_SIGNATURE;

    CryptHashStart(&hashState, hashAlg);
    CryptDigestUpdate2B(&hashState, &nonceK->b);
    CryptDigestUpdate2B(&hashState, &digest->b);
    hash2B->size = CryptHashEnd(&hashState, digestSize, hash2B->buffer);
    TpmMath_IntFrom2B(bnT, hash2B);
    if(!ExtMath_Mod(bnT, order) || ExtMath_IsZero(bnT))
        return TPM_RC_SIGNATURE;

    if(!ExtMath_Subtract(bnNegT, order, bnT))
        return TPM_RC_SIGNATURE;

    if(TpmEcc_PointMult(pointCheck, NULL, bnS, ecQ, bnNegT, E) != TPM_RC_SUCCESS)
        return TPM_RC_SIGNATURE;

    if(TpmEcc_PointMult(pointK, NULL, bnK, NULL, NULL, E) != TPM_RC_SUCCESS)
        return TPM_RC_SIGNATURE;

    if(!TpmEcc_PointTo2B(&lhs, pointCheck, E) || !TpmEcc_PointTo2B(&rhs, pointK, E))
        return TPM_RC_SIGNATURE;

    if(MemoryEqual2B(&lhs.x.b, &rhs.x.b) && MemoryEqual2B(&lhs.y.b, &rhs.y.b))
        retVal = TPM_RC_SUCCESS;

    return retVal;
}

#endif  // ALG_ECC && ALG_ECDAA
