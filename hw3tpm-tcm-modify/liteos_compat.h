// third_party/hw3tpm/liteos_compat.h
#ifndef LITEOS_COMPAT_H
#define LITEOS_COMPAT_H

// 1. 先取消 TPM 可能定义的冲突类型/宏（避免重复定义）
#undef UINT32
#undef BOOL
#undef NORETURN

// 2. 强制使用 LiteOS-M 的类型定义（从 los_compiler.h 导入）
#include "los_compiler.h"

// 3. 若 LiteOS-M 未定义某些 TPM 必需的类型，补充定义（按需添加）
// 例如：若 TPM 用到 UINT64 而 LiteOS-M 未定义，可添加
#ifndef UINT64
typedef uint64_t UINT64;
#endif

#endif  // LITEOS_COMPAT_H