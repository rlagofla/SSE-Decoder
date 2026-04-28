cmake_minimum_required(VERSION 3.16)
project(sse_decoder)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 复用同目录下 szse_decoder 项目中已经编译好的 PcapPlusPlus 库
set(PCAPP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../szse_decoder/3rd/pcapplusplus"
    CACHE PATH "PcapPlusPlus 安装根目录")

if(NOT EXISTS "${PCAPP_ROOT}/include/pcapplusplus/PcapFileDevice.h")
    message(FATAL_ERROR "未找到 PcapPlusPlus: ${PCAPP_ROOT}，"
                        "可通过 -DPCAPP_ROOT=<路径> 指定。")
endif()

include_directories(${PCAPP_ROOT}/include/pcapplusplus)

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
        "${PCAPP_ROOT}/lib64/libPcap++.a"
        "${PCAPP_ROOT}/lib64/libPacket++.a"
        "${PCAPP_ROOT}/lib64/libCommon++.a"
        pcap
        pthread
        ZLIB::ZLIB
    )
endforeach()

target_link_libraries(decode_47_4701 PRIVATE Iconv::Iconv)
