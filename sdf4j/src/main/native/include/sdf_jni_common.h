/*
 * Copyright (c) 2025 OpenHitls
 * SDF4J is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef SDF_JNI_COMMON_H
#define SDF_JNI_COMMON_H

#include "org_openhitls_sdf4j_SDF.h"
#include "org_openhitls_sdf4j_internal_NativeLibraryLoader.h"
#include "dynamic_loader.h"
#include "type_conversion.h"
#include "sdf_log.h"
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 标记未使用的参数以避免编译警告 */
#define UNUSED(x) (void)(x)

#ifdef __cplusplus
}
#endif

#endif /* SDF_JNI_COMMON_H */
