#!/bin/bash

# 目标服务器和路径
TARGET="sw-stock-sh"
REMOTE_DIR="~/sse_decoder"

# 确保远程目录存在
ssh $TARGET "mkdir -p $REMOTE_DIR"

# 0. 准备本地 libpcap 头文件 (因为目标机是离线的且缺少 libpcap-devel)
echo "正在从本地准备 libpcap 头文件..."
mkdir -p 3rd/pcap/include/pcap
cp /usr/include/pcap.h 3rd/pcap/include/ 2>/dev/null
cp /usr/include/pcap/*.h 3rd/pcap/include/pcap/ 2>/dev/null

# 1. rsync 同步
# 排除不需要的目录和文件，只同步必要的内容
echo "开始同步代码到 $TARGET..."
rsync -avzP \
    --exclude '.git' \
    --exclude '.claude' \
    --exclude 'build' \
    --exclude 'doc' \
    --exclude 'py' \
    --exclude 'research' \
    ./ $TARGET:$REMOTE_DIR/

echo "同步完成！"
echo "请登录 $TARGET 并执行以下命令进行离线编译："
echo "------------------------------------------------"
echo "cd $REMOTE_DIR"
echo "rm -rf build && mkdir build && cd build"
echo "cmake -DUSE_EFVI=ON \\"
echo "      -DPCAP_INCLUDE_DIR=$REMOTE_DIR/3rd/pcap/include \\"
echo "      -DPCAP_LIBRARY=/usr/lib64/libpcap.so.1 \\"
echo "      .."
echo "make -j"
echo "------------------------------------------------"
