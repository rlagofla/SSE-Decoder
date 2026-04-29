cmake_minimum_required(VERSION 3.16)

# 如果在 conda 环境里，自动使用 conda 的编译器
if(DEFINED ENV{CONDA_PREFIX})
    set(CMAKE_CXX_COMPILER "$ENV{CONDA_PREFIX}/bin/x86_64-conda-linux-gnu-g++")
    set(CMAKE_C_COMPILER   "$ENV{CONDA_PREFIX}/bin/x86_64-conda-linux-gnu-gcc")
endif()

project(sse_decoder)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 复用同目录下 szse_decoder 项目中已经编译好的 PcapPlusPlus 库
set(PCAPP_ROOT "$ENV{CONDA_PREFIX}")

include_directories(
    ${PCAPP_ROOT}/include/pcapplusplus
    ${PCAPP_ROOT}/include/
)

# 用 find_package 找 zlib/iconv 的头/库（conda env 里 iconv 是独立 libiconv，
# 不在 glibc 里，必须显式链接）
find_package(ZLIB  REQUIRED)
find_package(Iconv REQUIRED)

add_executable(extract_payload src/extract_payload.cpp)
add_executable(split_frames    src/split_frames.cpp)
add_executable(decode_47_4701  src/decode_47_4701.cpp)
add_executable(decode_6_3113   src/decode_6_3113.cpp)
add_executable(decode_9_5803   src/decode_9_5803.cpp)

# 静态库链接顺序必须是 Pcap++ -> Packet++ -> Common++
foreach(tgt extract_payload split_frames decode_47_4701 decode_6_3113 decode_9_5803)
    target_link_libraries(${tgt} PRIVATE
        "${PCAPP_ROOT}/lib/libPcap++.a"
        "${PCAPP_ROOT}/lib/libPacket++.a"
        "${PCAPP_ROOT}/lib/libCommon++.a"
        pcap
        pthread
        ZLIB::ZLIB
        stdc++fs
    )
endforeach()

target_link_libraries(decode_47_4701 PRIVATE Iconv::Iconv)
