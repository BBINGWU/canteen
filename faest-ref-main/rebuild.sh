#!/bin/bash

# 1. 定位 openssl@3 的路径
OPENSSL_PATH=$(brew --prefix openssl@3)

echo "Detected OpenSSL at: $OPENSSL_PATH"

# 2. 清理旧的 build 目录
echo "Removing old build directory..."
rm -rf build

# 3. 重新创建 build 目录
mkdir build
cd build

# 4. 重新 CMake 配置，指定 openssl 路径
echo "Running cmake..."
cmake .. -DOPENSSL_ROOT_DIR=$OPENSSL_PATH -DOPENSSL_LIBRARIES=$OPENSSL_PATH/lib

# 5. 用 Ninja 编译
echo "Running ninja build..."
ninja

echo "✅ Rebuild completed!"
