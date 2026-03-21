#!/bin/bash

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
SDFX_LIB_NAME=sdf_openhitls


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
    echo "Building sdfx library..."
    mkdir -p $SDFX_BUILD_DIR
    cd $SDFX_BUILD_DIR
    cmake .. || exit 1
    make -j$(nproc) || exit 1
    echo "sdfx library built successfully."
}

prepare_sdfx()
{
    clone_sdfx
    build_sdfx
}

build_sdf4j_with_simulator()
{
    echo "Building SDF4J with simulator..."
    cd $SDF4J_ROOT_DIR
    mvn clean package \
        -Dsdf.library.name=$SDFX_LIB_NAME \
        -Dsdf.library.path=$SDFX_BUILD_DIR || exit 1
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
