#!/bin/bash
set -euo pipefail

# Copyright (c) 2025 OpenHitls
# SDF4J is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SDF4J_ROOT_DIR=$(realpath "${SCRIPT_DIR}/..")
DEPEND_DIR="${SDF4J_ROOT_DIR}/platform"

SDFX_GIT_REPO_URL="https://gitcode.com/openHiTLS/sdfx.git"
SDFX_SIMULATOR_BRANCH="simulator"
SDFX_SOURCE_DIR="${DEPEND_DIR}/sdfx"
SDFX_BUILD_DIR="${SDFX_SOURCE_DIR}/build"
OPENHITLS_BUILD_DIR="${SDFX_SOURCE_DIR}/third_party/openhitls/build"
SDFX_LIB_NAME=sdf_openhitls
SDFX_LIB_PATH="${SDFX_BUILD_DIR}/lib${SDFX_LIB_NAME}.so"

ENABLE_ASAN=false
for arg in "$@"; do
    case "$arg" in
        asan)
            ENABLE_ASAN=true
            ;;
        *)
            echo "Usage: $0 [asan]"
            exit 1
            ;;
    esac
done

MAVEN_ASAN_OPTIONS=()
if [ "$ENABLE_ASAN" = true ]; then
    MAVEN_ASAN_OPTIONS=(-Dcmake.extra.options="-DCMAKE_C_FLAGS=-fsanitize=address -DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address")
fi


mk_depend_dir()
{
    if [ ! -d $DEPEND_DIR ]; then
        mkdir -p $DEPEND_DIR
        echo "Created depend directory at: $DEPEND_DIR"
    else
        echo "Depend directory already exists at: $DEPEND_DIR, skipping creation."
    fi
}

clone_sdfx()
{
    if [ ! -d $SDFX_SOURCE_DIR ]; then
        echo "Cloning sdfx repository..."
        git clone $SDFX_GIT_REPO_URL -b $SDFX_SIMULATOR_BRANCH $SDFX_SOURCE_DIR
    else
        echo "sdfx repository already cloned at: $SDFX_SOURCE_DIR, skipping clone."
    fi
}

build_sdfx()
{
    if [ "$ENABLE_ASAN" = true ]; then
        echo "Building sdfx library with AddressSanitizer..."
    else
        echo "Building sdfx library..."
    fi
    rm -rf "$SDFX_BUILD_DIR"
    mkdir -p "$SDFX_BUILD_DIR"

    if [ "$ENABLE_ASAN" = true ]; then
        cmake -S "$SDFX_SOURCE_DIR" -B "$SDFX_BUILD_DIR" \
            -DCMAKE_BUILD_TYPE=Debug \
            -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
            -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address"
    else
        cmake -S "$SDFX_SOURCE_DIR" -B "$SDFX_BUILD_DIR"
    fi

    cmake --build "$SDFX_BUILD_DIR" --clean-first -j"$(nproc)"
    echo "sdfx library built successfully."
}

prepare_sdfx()
{
    clone_sdfx
    build_sdfx
}

build_sdf4j_with_simulator()
{
    if [ "$ENABLE_ASAN" = true ]; then
        echo "Building SDF4J with AddressSanitizer..."
        export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:halt_on_error=1:abort_on_error=1}"
        export LD_PRELOAD="$(gcc -print-file-name=libasan.so)${LD_PRELOAD:+:${LD_PRELOAD}}"
    else
        echo "Building SDF4J..."
    fi

    cd "$SDF4J_ROOT_DIR"
    export LD_LIBRARY_PATH="${SDFX_BUILD_DIR}:${OPENHITLS_BUILD_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    export SDF_LIBRARY_NAME="${SDFX_LIB_NAME}"
    export SDF_LIBRARY_PATH="${SDFX_LIB_PATH}"

    rm -rf \
        "$SDF4J_ROOT_DIR/sdf4j/src/main/native/build" \
        "$SDF4J_ROOT_DIR/sdf4j-jce/src/main/native/build"

    mvn \
        -Pdebug \
        clean package \
        -Dcmake.build.type=Debug \
        -Dsdf.library.name="$SDFX_LIB_NAME" \
        -Dsdf.library.path="$SDFX_BUILD_DIR" \
        "${MAVEN_ASAN_OPTIONS[@]}"
    echo "SDF4J built successfully."
    mvn javadoc:javadoc -pl sdf4j -Dadditionalparam=-Xwerror || exit 1
}

echo "Current script directory: ${SCRIPT_DIR}"
echo "SDF4J root directory: ${SDF4J_ROOT_DIR}"

# create depend dir
mk_depend_dir
# prepare sdfx
prepare_sdfx
# build sdf4j with simulator
build_sdf4j_with_simulator
