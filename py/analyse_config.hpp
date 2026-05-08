#pragma once
// analyse_config.hpp — 分析配置，修改后重新编译即可，不需要命令行参数

#include <string>
#include <vector>

// 待分析的 pcap 文件路径
inline const std::string PCAP_FILE = "20260114_enp1s0f1np1.pcap";

// 输出文件路径
inline const std::string OUT_SRC_IP_PORT    = "info/src_ip_port.csv";
inline const std::string OUT_DST_IP_PORT    = "info/dst_ip_port.csv";
inline const std::string OUT_PER_MINUTE     = "info/per_minute.csv";
inline const std::string OUT_PROTO_ALL      = "info/proto_all.csv";      // 全量包协议分布
inline const std::string OUT_PROTO_MATCHED  = "info/proto_matched.csv";  // 命中端口的包协议分布

// 端口过滤：空则统计所有端口；非空则源端口或目的端口匹配任意一个即算
// 例如 {3202, 3203}
inline const std::vector<int> FILTER_PORTS = {5261};

// 命中包 payload 打印字节数：0 = 不打印，-1 = 全打，正整数 = 最多打印前 N 字节
inline const int PAYLOAD_PRINT_BYTES = 0;
