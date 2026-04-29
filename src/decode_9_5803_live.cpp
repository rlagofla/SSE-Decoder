// decode_9_5803_live.cpp — 上交所 (9, 5803) 逐笔行情解码器 (实时网卡输入)
//
// 用法:
//   decode_9_5803_live <iface> [filter_port=5261] [--csv|--raw-csv]
//
// 示例:
//   decode_9_5803_live en0 5261 --csv
//   Ctrl-C 停止抓包

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>

#include "9_5803_decode_engine.hpp"

static std::atomic<bool> g_stop{false};

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "用法: " << argv[0]
                  << " <iface> [filter_port=5261] [--csv|--raw-csv]\n"
                  << "  iface      : 网卡名称 (如 en0, eth0)\n"
                  << "  --csv      : 业务 CSV, 列对齐 通联 mdl_*.csv\n"
                  << "  --raw-csv  : 原始 FAST ints, 调试用\n";
        return 1;
    }

    uint16_t filter_port = (argc >= 3) ? uint16_t(std::stoi(argv[2])) : 5261;
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--csv")     g_mode = OutMode::BizCsv;
        else if (a == "--raw-csv") g_mode = OutMode::RawCsv;
    }

    signal(SIGINT,  [](int){ g_stop = true; });
    signal(SIGTERM, [](int){ g_stop = true; });

    pcpp::PcapLiveDevice* dev =
        pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(argv[1]);
    if (!dev) {
        std::cerr << "找不到网卡: " << argv[1] << "\n";
        std::cerr << "可用网卡:\n";
        for (auto* d : pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList())
            std::cerr << "  " << d->getName() << "\n";
        return 1;
    }

    if (!dev->open()) {
        std::cerr << "打开网卡失败: " << argv[1] << "\n";
        return 1;
    }

    if (filter_port != 0) {
        std::string bpf = "tcp port " + std::to_string(filter_port);
        if (!dev->setFilter(bpf)) {
            std::cerr << "[warn] 设置 BPF 过滤器失败: " << bpf << "\n";
        }
    }

    Context ctx;
    ctx.filter_port = filter_port;
    ctx.max_frames  = 0;

    pcpp::TcpReassembly reassembly(onTcpData, &ctx, onConnStart, onConnEnd);

    auto onPacket = [](pcpp::RawPacket* pkt, pcpp::PcapLiveDevice*, void* ud) {
        static_cast<pcpp::TcpReassembly*>(ud)->reassemblePacket(pkt);
    };
    if (!dev->startCapture(onPacket, &reassembly)) {
        std::cerr << "启动抓包失败\n";
        dev->close();
        return 1;
    }

    std::cerr << "[live] 开始抓包: " << argv[1]
              << "  port=" << filter_port << "\n";

    while (!g_stop)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cerr << "\n[live] 停止...\n";
    dev->stopCapture();
    reassembly.closeAllConnections();
    dev->close();
    return 0;
}
