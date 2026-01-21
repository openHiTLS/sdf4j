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

project(sdf4j-jce VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 查找JNI
find_package(JNI REQUIRED)
if(JNI_FOUND)
    message(STATUS "JNI include directories: ${JNI_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "JNI not found")
endif()

# sdf4j native目录（包含公共头文件和源文件）
if(NOT DEFINED SDF4J_NATIVE_DIR)
    set(SDF4J_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../sdf4j/src/main/native")
endif()
message(STATUS "SDF4J native directory: ${SDF4J_NATIVE_DIR}")

# 包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SDF4J_NATIVE_DIR}/include
    ${JNI_INCLUDE_DIRS}
)

# 公共源文件（来自sdf4j）
# 注意：不包含jni_cache.c和type_conversion.c，因为它们引用sdf4j core的Java类
set(COMMON_SOURCES
    ${SDF4J_NATIVE_DIR}/src/dynamic_loader.c
    ${SDF4J_NATIVE_DIR}/src/sdf_log.c
)

# JCE特有源文件
set(JCE_SOURCES
    src/sdf_jce_init.c
    src/session_pool.c
    src/auth_manager.c
    src/sdf_jce_sm3.c
    src/sdf_jce_sm4.c
    src/sdf_jce_sm2.c
    src/sdf_jce_mac.c
    src/sdf_jce_random.c
    src/sdf_jce_keygen.c
)

# 头文件
set(HEADERS
    include/session_pool.h
    include/auth_manager.h
    include/jce_common.h
)

# 创建共享库
add_library(sdf4j-jce SHARED ${COMMON_SOURCES} ${JCE_SOURCES} ${HEADERS})

# 链接库
target_link_libraries(sdf4j-jce PRIVATE dl pthread)

# 设置输出目录
set(OUTPUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../target/native")
set_target_properties(sdf4j-jce PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}
)

# 编译选项
target_compile_options(sdf4j-jce PRIVATE
    -Wall
    -Wextra
    -Werror
    -fPIC
)

# 根据构建类型设置优化选项
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(sdf4j-jce PRIVATE -g -O0)
    message(STATUS "Debug build - optimizations disabled, logging enabled")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(sdf4j-jce PRIVATE -O2 -DNDEBUG)
    message(STATUS "Release build - optimizations enabled, logging disabled")
else()
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
    target_compile_options(sdf4j-jce PRIVATE -g -O2 -DNDEBUG)
    message(STATUS "RelWithDebInfo build - logging disabled")
endif()

# 安装配置
install(TARGETS sdf4j-jce
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# 打印构建信息
message(STATUS "==================================================")
message(STATUS "SDF4J JCE JNI Library Configuration")
message(STATUS "==================================================")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Output directory: ${OUTPUT_DIR}")
message(STATUS "==================================================")
