#pragma once
// config.hpp — TOML 配置文件解析

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <toml++/toml.hpp>

struct IfaceConfig {
    std::string iface;                             // 网卡名（来自 run.source）
    std::string backend                = "pcap";
    bool        promisc                = true;
    int         snaplen                = 65535;
    int         capture_cpu            = -1;       // iface 抓包+解码主线程绑核（-1 = 不绑核）
    int         open_max_attempts      = 30;
    int         open_retry_ms          = 2000;

    // pcap dump（可选）：若 dump_pcap 非空，则把抓到的每个 frame 写入该 pcap 文件
    std::string dump_pcap              = "";       // 空 = 不 dump；非空 = pcap 输出路径
    size_t      dump_pool_size         = 1u << 20; // RawPacketBuf 池容量（默认 1M ≈ 2GB）
    int         dump_cpu               = -1;       // dump 线程绑核（-1 = 不绑核）
};

struct TypeConfig {
    uint32_t    category_id;
    uint32_t    msg_type;
    std::string output;   // CSV 输出文件路径
    bool        dedup = true;
};

struct Config {
    std::string          mode      = "pcap";   // "pcap" 或 "iface"
    std::string          source;               // pcap 路径 或 网卡名
    uint16_t             port      = 9129;
    std::string          log_level = "info";   // trace/debug/info/warn/error
    std::vector<TypeConfig> types;
    IfaceConfig             iface;
};

inline Config loadConfig(const std::string& path) {
    toml::table tbl;
    try {
        tbl = toml::parse_file(path);
    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("TOML 解析错误: ") + std::string(e.description()));
    }

    Config cfg;
    cfg.mode      = tbl["run"]["mode"].value_or(std::string("pcap"));
    cfg.source    = tbl["run"]["source"].value_or(std::string(""));
    cfg.port      = static_cast<uint16_t>(tbl["run"]["port"].value_or(int64_t(9129)));
    cfg.log_level = tbl["log"]["level"].value_or(std::string("info"));

    if (auto* arr = tbl["decode"].as_array()) {
        for (auto&& elem : *arr) {
            if (auto* t = elem.as_table()) {
                TypeConfig tc;
                tc.category_id = static_cast<uint32_t>((*t)["category_id"].value_or(int64_t(0)));
                tc.msg_type    = static_cast<uint32_t>((*t)["msg_type"].value_or(int64_t(0)));
                tc.output = (*t)["output"].value_or(std::string(""));
                tc.dedup  = (*t)["dedup"].value_or(true);
                cfg.types.push_back(std::move(tc));
            }
        }
    }

    cfg.iface.backend       = tbl["iface"]["backend"].value_or(std::string("pcap"));
    cfg.iface.promisc       = tbl["iface"]["promisc"].value_or(true);
    cfg.iface.snaplen       = static_cast<int>(tbl["iface"]["snaplen"].value_or(int64_t(65535)));
    cfg.iface.capture_cpu   = static_cast<int>(tbl["iface"]["capture_cpu"].value_or(int64_t(-1)));
    cfg.iface.open_max_attempts = static_cast<int>(tbl["iface"]["open_max_attempts"].value_or(int64_t(30)));
    cfg.iface.open_retry_ms     = static_cast<int>(tbl["iface"]["open_retry_ms"].value_or(int64_t(2000)));
    cfg.iface.dump_pcap         = tbl["iface"]["dump_pcap"].value_or(std::string(""));
    cfg.iface.dump_pool_size    = static_cast<size_t>(tbl["iface"]["dump_pool_size"].value_or(int64_t(1) << 20));
    cfg.iface.dump_cpu          = static_cast<int>(tbl["iface"]["dump_cpu"].value_or(int64_t(-1)));

    if (cfg.source.empty())
        throw std::runtime_error("配置文件缺少 run.source 字段");
    if (cfg.types.empty())
        throw std::runtime_error("配置文件缺少 [[decode]] 类型定义");

    return cfg;
}
