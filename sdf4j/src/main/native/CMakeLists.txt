# Copyright (c) 2025 OpenHitls
# SDF4J is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.10)

# 项目信息
project(sdf4j-jni VERSION 1.0.0 LANGUAGES C)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 查找JNI
find_package(JNI REQUIRED)
if(JNI_FOUND)
    message(STATUS "JNI include directories: ${JNI_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "JNI not found")
endif()

# SDF库路径配置
# 注意: SDF头文件已包含在项目中(include/目录下)，编译时无需外部依赖
# SDF库在运行时通过系统属性或环境变量动态加载，编译时不需要指定路径

# 包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${JNI_INCLUDE_DIRS}
)

# 源文件
set(SOURCES
    src/jni_cache.c
    src/dynamic_loader.c
    src/type_conversion.c
    src/sdf_log.c
    src/sdf_jni_log.c
    src/sdf_jni_loader.c
    src/sdf_jni_device.c
    src/sdf_jni_key.c
    src/sdf_jni_keygen.c
    src/sdf_jni_asymmetric.c
    src/sdf_jni_symmetric.c
    src/sdf_jni_file.c
    src/sdf_jni_util.c
)

# 头文件
set(HEADERS
    include/jni_cache.h
    include/dynamic_loader.h
    include/type_conversion.h
    include/sdf_log.h
    include/sdf_jni_common.h
    include/org_openhitls_sdf4j_SDF.h
    include/org_openhitls_sdf4j_internal_NativeLibraryLoader.h
)

# 创建共享库
add_library(sdf4j-jni SHARED ${SOURCES} ${HEADERS})

# 链接库（dlopen/dlsym 所需的 dl 库）
target_link_libraries(sdf4j-jni PRIVATE dl)

# 设置输出目录
set(OUTPUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../target/native")
set_target_properties(sdf4j-jni PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}
)

# 编译选项
target_compile_options(sdf4j-jni PRIVATE
    -Wall
    -Wextra
    -Werror
    -fPIC
)

# 根据构建类型设置优化选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(sdf4j-jni PRIVATE -g -O0)
    message(STATUS "Debug build - optimizations disabled")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(sdf4j-jni PRIVATE -O2 -DNDEBUG)
    message(STATUS "Release build - optimizations enabled")
else()
    # 默认为 RelWithDebInfo
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
    target_compile_options(sdf4j-jni PRIVATE -g -O2)
    message(STATUS "RelWithDebInfo build")
endif()

# 安装配置（可选）
install(TARGETS sdf4j-jni
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# 打印构建信息
message(STATUS "==================================================")
message(STATUS "SDF4J JNI Library Configuration")
message(STATUS "==================================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Output directory: ${OUTPUT_DIR}")
message(STATUS "==================================================")
