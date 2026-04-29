// decode_9_5803.cpp — 上交所 (9, 5803) 逐笔行情解码器 (pcap 文件输入)
//
// 用法:
//   decode_9_5803 <pcap> [filter_port=5261] [max_frames_per_stream=0] [--csv|--raw-csv]

#include <iostream>
#include <PcapFileDevice.h>
#include <Packet.h>

#include "9_5803_decode_engine.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0]
                  << " <pcap> [filter_port=5261] [max_frames_per_stream=0] [--csv|--raw-csv]\n"
                  << "  --csv      : 业务 CSV, 列对齐 通联 mdl_*.csv\n"
                  << "  --raw-csv  : 原始 FAST ints, 调试用\n";
        return 1;
    }

    Context ctx;
    ctx.filter_port = (argc >= 3) ? uint16_t(std::stoi(argv[2])) : 5261;
    ctx.max_frames  = (argc >= 4) ? size_t(std::stoul(argv[3])) : 0;
    for (int i = 4; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--csv")     g_mode = OutMode::BizCsv;
        else if (a == "--raw-csv") g_mode = OutMode::RawCsv;
    }

    pcpp::PcapFileReaderDevice reader(argv[1]);
    if (!reader.open()) {
        std::cerr << "打开 pcap 失败: " << argv[1] << "\n";
        return 1;
    }

    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);
    pcpp::RawPacket     raw;
    while (!g_done && reader.getNextPacket(raw)) reassembly.reassemblePacket(&raw);
    reassembly.closeAllConnections();
    reader.close();
    return 0;
}
