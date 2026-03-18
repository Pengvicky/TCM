#include "BnOhitls.h"

#ifdef MATH_LIB_OHITLS

#include <stdint.h>
#include <string.h>

#include <crypto/bn/include/crypt_bn.h>
#include <crypto/ecc/include/crypt_ecc.h>
#include <crypto/ecc/src/ecc_local.h>
#include <include/crypto/crypt_errno.h>
#include <BnValues.h>

int32_t ECC_Point2Affine(const ECC_Para *para, ECC_Point *r, const ECC_Point *a);

#define HITLS_RET_OK(ret) ((ret) == CRYPT_SUCCESS)

static BN_BigNum *WrapConstBn(BN_BigNum *target, bigConst value)
{
    if (target == NULL || value == NULL) {
        FAIL(FATAL_ERROR_INTERNAL);
    }
    // BN_Init(target, (BN_UINT *)BnGetArray(value), BnGetAllocated(value), 1);
    target->data = (BN_UINT *)BnGetArray(value);
    target->room = BnGetAllocated(value);
    target->flag = CRYPT_BN_FLAG_STATIC;
    target->size = BnGetSize(value);
    target->sign = false;
    return target;
}

static BN_BigNum *WrapMutableBn(BN_BigNum *target, bigNum value)
{
    if (target == NULL || value == NULL) {
        FAIL(FATAL_ERROR_INTERNAL);
    }
    // BN_Init(target, (BN_UINT *)BnGetArray(value), BnGetAllocated(value), 1);
    target->data = (BN_UINT *)BnGetArray(value);
    target->room = BnGetAllocated(value);
    target->flag = CRYPT_BN_FLAG_STATIC;
    target->size = BnGetSize(value);
    target->sign = false;
    return target;
}

static void SyncResultBigNum(bigNum target, const BN_BigNum *source)
{
    if (target == NULL || source == NULL) {
        FAIL(FATAL_ERROR_INTERNAL);
    }
    BnSetTop(target, source->size);
}

static BN_Optimizer *RequireOptimizer(void)
{
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        FAIL(FATAL_ERROR_ALLOCATION);
    }
    return opt;
}

static BOOL CopyHitlsToTpmBn(const BN_BigNum *src, bigNum dst)
{
    if (src == NULL || dst == NULL) {
        return FALSE;
    }
    if (src->size > BnGetAllocated(dst)) {
        return FALSE;
    }
    if (src->size > 0) {
        (void)memcpy(BnGetArray(dst), src->data, src->size * sizeof(BN_UINT));
    }
    if (src->size < BnGetAllocated(dst)) {
        memset(BnGetArray(dst) + src->size, 0,
               (BnGetAllocated(dst) - src->size) * sizeof(BN_UINT));
    }
    BnSetTop(dst, src->size);
    return TRUE;
}

static BOOL CopyTpmToHitlsBn(BN_BigNum *dst, bigConst src)
{
    if (dst == NULL) {
        return FALSE;
    }
    if (src == NULL) {
        (void)BN_Zeroize(dst);
        return TRUE;
    }
    uint32_t words = BnGetSize(src);
    if (words > dst->room) {
        if (!HITLS_RET_OK(BN_Extend(dst, words))) {
            return FALSE;
        }
    }
    if (words > 0) {
        (void)memcpy(dst->data, BnGetArray(src), words * sizeof(BN_UINT));
    }
    dst->size = words;
    dst->sign = false;
    BN_FixSize(dst);
    return TRUE;
}

#if LIBRARY_COMPATIBILITY_CHECK
BOOL BnMathLibraryCompatibilityCheck(void)
{
    static const BYTE test[] = {
        0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18,
        0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
    BN_VAR(tpmBn, sizeof(test) * 8);
    BN_BigNum mirror;
    BnFromBytes(tpmBn, test, sizeof(test));
    WrapMutableBn(&mirror, tpmBn);
    BN_BigNum *dup = BN_Create(sizeof(test) * 8);
    if (dup == NULL) {
        return FALSE;
    }
    BOOL ok = FALSE;
    if (HITLS_RET_OK(BN_Bin2Bn(dup, test, sizeof(test))) && dup->size == mirror.size) {
        ok = (memcmp(dup->data, mirror.data, dup->size * sizeof(BN_UINT)) == 0);
    }
    BN_Destroy(dup);
    return ok;
}
#endif

LIB_EXPORT BOOL BnModMult(bigNum result, bigConst op1, bigConst op2, bigConst modulus)
{
    BN_BigNum bnResult, bnOp1, bnOp2, bnMod;
    WrapMutableBn(&bnResult, result);
    WrapConstBn(&bnOp1, op1);
    WrapConstBn(&bnOp2, op2);
    WrapConstBn(&bnMod, modulus);
    BN_Optimizer *opt = RequireOptimizer();
    int32_t ret = BN_ModMul(&bnResult, &bnOp1, &bnOp2, &bnMod, opt);
    BN_OptimizerDestroy(opt);
    if (!HITLS_RET_OK(ret)) {
        return FALSE;
    }
    SyncResultBigNum(result, &bnResult);
    return TRUE;
}

LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier)
{
    BN_BigNum bnResult, bnA, bnB;
    BN_BigNum tempResult;
    BN_BigNum *pOut = NULL;
    BOOL success = FALSE;

    WrapConstBn(&bnA, multiplicand);
    WrapConstBn(&bnB, multiplier);
    
    // 别名检查
    BOOL isAliased = (result == (bigNum)multiplicand) || (result == (bigNum)multiplier);
    
    if (isAliased) {
        // 使用堆分配或缓冲区池，避免栈溢出
        uint32_t tempDataRoom = bnA.room + bnB.room;
        BN_UINT* tempData = (BN_UINT*)malloc(tempDataRoom * sizeof(BN_UINT));
        if (!tempData) {
            return FALSE; // 内存分配失败
        }
        tempResult.data = tempData;
        tempResult.room = tempDataRoom;
        tempResult.flag = CRYPT_BN_FLAG_STATIC;
        tempResult.size = 0;
        tempResult.sign = false;
        pOut = &tempResult;
    } else {
        WrapMutableBn(&bnResult, result);
        pOut = &bnResult;
    }

    BN_Optimizer *opt = RequireOptimizer();
    int32_t ret = BN_Mul(pOut, &bnA, &bnB, opt);
    BN_OptimizerDestroy(opt);

    if (HITLS_RET_OK(ret)) {
        // 统一同步结果
        if (isAliased) {
            // 别名情况：需要从临时缓冲区拷贝数据到result
            // 1. 确保result有足够的空间
            if (pOut->size > BnGetAllocated(result)) {
                // 内存不足，释放临时内存并返回失败
                free(tempResult.data);
                return FALSE;
            }
            // 2. 拷贝数据
            memcpy(result->d, pOut->data, pOut->size * sizeof(BN_UINT));
        } 
        SyncResultBigNum(result, pOut);
        success = TRUE;
    }

    // 清理临时内存
    if (isAliased && tempResult.data) {
        free(tempResult.data);
    }

    return success;
}

/* LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier)
{
    BN_BigNum bnResult, bnA, bnB;
    WrapMutableBn(&bnResult, result);
    WrapConstBn(&bnA, multiplicand);
    WrapConstBn(&bnB, multiplier);
    BN_Optimizer *opt = RequireOptimizer();
    int32_t ret = BN_Mul(&bnResult, &bnA, &bnB, opt);
    BN_OptimizerDestroy(opt);
    if (!HITLS_RET_OK(ret)) {
        return FALSE;
    }
    SyncResultBigNum(result, &bnResult);
    return TRUE;
} */

LIB_EXPORT BOOL BnDiv(bigNum quotient, bigNum remainder, bigConst dividend, bigConst divisor)
{
    BN_BigNum bnDividend, bnDivisor;
    WrapConstBn(&bnDividend, dividend);
    WrapConstBn(&bnDivisor, divisor);
    BN_BigNum bnQuotient, bnRemainder;
    BN_BigNum *qPtr = NULL;
    BN_BigNum *rPtr = NULL;
    if (quotient != NULL) {
        WrapMutableBn(&bnQuotient, quotient);
        qPtr = &bnQuotient;
    }
    if (remainder != NULL) {
        WrapMutableBn(&bnRemainder, remainder);
        rPtr = &bnRemainder;
    }
    BN_Optimizer *opt = RequireOptimizer();
    if (BnEqualZero(divisor)) {
        BN_OptimizerDestroy(opt);
        FAIL(FATAL_ERROR_DIVIDE_ZERO);
    }
    int32_t ret = BN_Div(qPtr, rPtr, &bnDividend, &bnDivisor, opt);
    BN_OptimizerDestroy(opt);
    if (!HITLS_RET_OK(ret)) {
        return FALSE;
    }
    if (quotient != NULL) {
        SyncResultBigNum(quotient, qPtr);
    }
    if (remainder != NULL) {
        SyncResultBigNum(remainder, rPtr);
    }
    return TRUE;
}

#if ALG_RSA
LIB_EXPORT BOOL BnGcd(bigNum gcd, bigConst number1, bigConst number2)
{
    BN_BigNum bnGcd, bnA, bnB;
    WrapMutableBn(&bnGcd, gcd);
    WrapConstBn(&bnA, number1);
    WrapConstBn(&bnB, number2);
    BN_Optimizer *opt = RequireOptimizer();
    int32_t ret = BN_Gcd(&bnGcd, &bnA, &bnB, opt);
    BN_OptimizerDestroy(opt);
    if (!HITLS_RET_OK(ret)) {
        return FALSE;
    }
    SyncResultBigNum(gcd, &bnGcd);
    return TRUE;
}

LIB_EXPORT BOOL BnModExp(bigNum result, bigConst number, bigConst exponent, bigConst modulus)
{
    BN_BigNum bnResult, bnNumber, bnExponent, bnModulus;
    WrapMutableBn(&bnResult, result);
    WrapConstBn(&bnNumber, number);
    WrapConstBn(&bnExponent, exponent);
    WrapConstBn(&bnModulus, modulus);
    BN_Optimizer *opt = RequireOptimizer();
    int32_t ret = BN_ModExp(&bnResult, &bnNumber, &bnExponent, &bnModulus, opt);
    BN_OptimizerDestroy(opt);
    if (!HITLS_RET_OK(ret)) {
        return FALSE;
    }
    SyncResultBigNum(result, &bnResult);
    return TRUE;
}
#endif

LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus)
{
    BN_BigNum bnResult, bnNumber, bnModulus;
    WrapMutableBn(&bnResult, result);
    WrapConstBn(&bnNumber, number);
    WrapConstBn(&bnModulus, modulus);
    BN_Optimizer *opt = RequireOptimizer();
    int32_t ret = BN_ModInv(&bnResult, &bnNumber, &bnModulus, opt);
    BN_OptimizerDestroy(opt);
    if (!HITLS_RET_OK(ret)) {
        return FALSE;
    }
    SyncResultBigNum(result, &bnResult);
    return TRUE;
}

#if ALG_ECC
static CRYPT_PKEY_ParaId MapCurveId(TPM_ECC_CURVE curveId)
{
    switch (curveId) {
    case TPM_ECC_NIST_P224:
        return CRYPT_ECC_NISTP224;
    case TPM_ECC_NIST_P256:
        return CRYPT_ECC_NISTP256;
    case TPM_ECC_NIST_P384:
        return CRYPT_ECC_NISTP384;
    case TPM_ECC_NIST_P521:
        return CRYPT_ECC_NISTP521;
    case TPM_ECC_SM2_P256:
        return CRYPT_ECC_SM2;
    case TPM_ECC_BP_P256_R1:
        return CRYPT_ECC_BRAINPOOLP256R1;
    case TPM_ECC_BP_P384_R1:
        return CRYPT_ECC_BRAINPOOLP384R1;
    case TPM_ECC_BP_P512_R1:
        return CRYPT_ECC_BRAINPOOLP512R1;
    default:
        return CRYPT_PKEY_PARAID_MAX;
    }
}

static BOOL CopyTpmPointToHitls(const bigCurveData *E, pointConst src, ECC_Point **dst)
{
    if (dst == NULL) {
        return FALSE;
    }
    if (src == NULL) {
        *dst = NULL;
        return TRUE;
    }
    ECC_Point *pt = ECC_NewPoint(E->para);
    if (pt == NULL) {
        FAIL(FATAL_ERROR_ALLOCATION);
    }
    if (!CopyTpmToHitlsBn(pt->x, src->x) ||
        !CopyTpmToHitlsBn(pt->y, src->y) ||
        !CopyTpmToHitlsBn(pt->z, src->z)) {
        ECC_FreePoint(pt);
        return FALSE;
    }
    *dst = pt;
    return TRUE;
}

static BOOL ExportHitlsPoint(const bigCurveData *E, ECC_Point *src, bigPoint dst)
{
    if (src == NULL || dst == NULL) {
        return FALSE;
    }
    if (BN_IsZero(src->z)) {
        BnSetTop(dst->x, 0);
        BnSetTop(dst->y, 0);
        BnSetTop(dst->z, 0);
        return FALSE;
    }
    if (!HITLS_RET_OK(ECC_Point2Affine(E->para, src, src))) {
        return FALSE;
    }
    if (!CopyHitlsToTpmBn(src->x, dst->x) ||
        !CopyHitlsToTpmBn(src->y, dst->y) ||
        !CopyHitlsToTpmBn(src->z, dst->z)) {
        return FALSE;
    }
    return !BnEqualZero(dst->z);
}

LIB_EXPORT bigCurveData *BnCurveInitialize(bigCurveData *E, TPM_ECC_CURVE curveId)
{
    if (E == NULL) {
        return NULL;
    }
    memset(E, 0, sizeof(*E));
    const TPMBN_ECC_CURVE_CONSTANTS *C = BnGetCurveData(curveId);
    if (C == NULL) {
        return NULL;
    }
    CRYPT_PKEY_ParaId paraId = MapCurveId(curveId);
    if (paraId == CRYPT_PKEY_PARAID_MAX) {
        return NULL;
    }
    ECC_Para *para = ECC_NewPara(paraId);
    if (para == NULL) {
        FAIL(FATAL_ERROR_ALLOCATION);
    }
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        ECC_FreePara(para);
        FAIL(FATAL_ERROR_ALLOCATION);
    }
    E->C = C;
    E->para = para;
    E->opt = opt;
    return E;
}

LIB_EXPORT void BnCurveFree(bigCurveData *E)
{
    if (E == NULL) {
        return;
    }
    if (E->para != NULL) {
        ECC_FreePara(E->para);
        E->para = NULL;
    }
    if (E->opt != NULL) {
        BN_OptimizerDestroy(E->opt);
        E->opt = NULL;
    }
    E->C = NULL;
}

LIB_EXPORT BOOL BnEccModMult(bigPoint R, pointConst S, bigConst d, const bigCurveData *E)
{
    if (R == NULL || d == NULL || E == NULL || E->para == NULL) {
        return FALSE;
    }
    const TPMBN_ECC_CURVE_CONSTANTS *constants = AccessCurveConstants(E);
    if (constants == NULL) {
        return FALSE;
    }
    ECC_Point *result = ECC_NewPoint(E->para);
    if (result == NULL) {
        FAIL(FATAL_ERROR_ALLOCATION);
    }
    ECC_Point *pointS = NULL;
    BOOL generator = FALSE;
    if (S == NULL) {
        generator = TRUE;
    } else {
        const constant_point_t *base = &constants->base;
        if (S == (pointConst)base) {
            generator = TRUE;
        }
    }
    if (!generator) {
        if (!CopyTpmPointToHitls(E, S, &pointS)) {
            ECC_FreePoint(result);
            return FALSE;
        }
    }
    BN_BigNum bnD;
    WrapConstBn(&bnD, d);
    int32_t ret = ECC_PointMul(E->para, result, &bnD, generator ? NULL : pointS);
    BOOL ok = FALSE;
    if (HITLS_RET_OK(ret)) {
        ok = ExportHitlsPoint(E, result, R);
    }
    ECC_FreePoint(pointS);
    ECC_FreePoint(result);
    return ok && HITLS_RET_OK(ret);
}

LIB_EXPORT BOOL BnEccModMult2(bigPoint R,
                              pointConst S,
                              bigConst d,
                              pointConst Q,
                              bigConst u,
                              const bigCurveData *E)
{
    if (R == NULL || Q == NULL || d == NULL || u == NULL || E == NULL || E->para == NULL) {
        return FALSE;
    }
    const TPMBN_ECC_CURVE_CONSTANTS *constants = AccessCurveConstants(E);
    if (constants == NULL) {
        return FALSE;
    }
    ECC_Point *pointS = NULL;
    ECC_Point *pointQ = NULL;
    ECC_Point *prodS = NULL;
    ECC_Point *prodQ = NULL;
    ECC_Point *sum = NULL;
    BOOL ok = FALSE;

    BOOL generator = FALSE;
    if (S == NULL) {
        generator = TRUE;
    } else {
        const constant_point_t *base = &constants->base;
        if (S == (pointConst)base) {
            generator = TRUE;
        }
    }

    if (!CopyTpmPointToHitls(E, Q, &pointQ) || pointQ == NULL) {
        goto cleanup;
    }
    if (!generator) {
        if (!CopyTpmPointToHitls(E, S, &pointS)) {
            goto cleanup;
        }
    }

    prodS = ECC_NewPoint(E->para);
    prodQ = ECC_NewPoint(E->para);
    sum = ECC_NewPoint(E->para);
    if (prodS == NULL || prodQ == NULL || sum == NULL) {
        FAIL(FATAL_ERROR_ALLOCATION);
    }

    BN_BigNum bnD, bnU;
    WrapConstBn(&bnD, d);
    WrapConstBn(&bnU, u);

    if (!HITLS_RET_OK(ECC_PointMul(E->para, prodS, &bnD, generator ? NULL : pointS))) {
        goto cleanup;
    }
    if (!HITLS_RET_OK(ECC_PointMul(E->para, prodQ, &bnU, pointQ))) {
        goto cleanup;
    }
    if (!HITLS_RET_OK(ECC_PointAddAffine(E->para, sum, prodS, prodQ))) {
        goto cleanup;
    }
    ok = ExportHitlsPoint(E, sum, R);

cleanup:
    ECC_FreePoint(sum);
    ECC_FreePoint(prodQ);
    ECC_FreePoint(prodS);
    ECC_FreePoint(pointQ);
    ECC_FreePoint(pointS);
    return ok;
}

LIB_EXPORT BOOL BnEccAdd(bigPoint R, pointConst S, pointConst Q, const bigCurveData *E)
{
    if (R == NULL || S == NULL || Q == NULL || E == NULL || E->para == NULL) {
        return FALSE;
    }
    if (AccessCurveConstants(E) == NULL) {
        return FALSE;
    }
    ECC_Point *pointS = NULL;
    ECC_Point *pointQ = NULL;
    ECC_Point *sum = NULL;
    BOOL ok = FALSE;

    if (!CopyTpmPointToHitls(E, S, &pointS) || pointS == NULL) {
        goto cleanup;
    }
    if (!CopyTpmPointToHitls(E, Q, &pointQ) || pointQ == NULL) {
        goto cleanup;
    }
    sum = ECC_NewPoint(E->para);
    if (sum == NULL) {
        FAIL(FATAL_ERROR_ALLOCATION);
    }
    if (!HITLS_RET_OK(ECC_PointAddAffine(E->para, sum, pointS, pointQ))) {
        goto cleanup;
    }
    ok = ExportHitlsPoint(E, sum, R);

cleanup:
    ECC_FreePoint(sum);
    ECC_FreePoint(pointQ);
    ECC_FreePoint(pointS);
    return ok;
}
#endif

#if CRYPTO_LIB_REPORTING
void BnGetImplementation(_CRYPTO_IMPL_DESCRIPTION *result)
{
    if (result != NULL) {
        OhitlsGetVersion(result);
    }
}
#endif

#endif /* MATH_LIB_OHITLS */