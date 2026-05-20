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
    std::string bin_dir                = "bin/";
    std::string bin_prefix             = "";
    uint64_t    segment_bytes          = 256ull << 20;
    bool        promisc                = true;
    int         snaplen                = 65535;
    int         writer_cpu             = -1;
    int         reader_cpu             = -1;
    int         open_max_attempts      = 30;
    int         open_retry_ms          = 2000;
    bool        delete_bin_after_read  = false;
    bool        flush_csv_per_segment  = true;
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
    cfg.iface.bin_dir       = tbl["iface"]["bin_dir"].value_or(std::string("bin/"));
    cfg.iface.bin_prefix    = tbl["iface"]["bin_prefix"].value_or(std::string(""));
    cfg.iface.segment_bytes = static_cast<uint64_t>(
        tbl["iface"]["segment_bytes"].value_or(int64_t(256) * 1024 * 1024));
    cfg.iface.promisc       = tbl["iface"]["promisc"].value_or(true);
    cfg.iface.snaplen       = static_cast<int>(tbl["iface"]["snaplen"].value_or(int64_t(65535)));
    cfg.iface.writer_cpu    = static_cast<int>(tbl["iface"]["writer_cpu"].value_or(int64_t(-1)));
    cfg.iface.reader_cpu    = static_cast<int>(tbl["iface"]["reader_cpu"].value_or(int64_t(-1)));
    cfg.iface.open_max_attempts = static_cast<int>(tbl["iface"]["open_max_attempts"].value_or(int64_t(30)));
    cfg.iface.open_retry_ms     = static_cast<int>(tbl["iface"]["open_retry_ms"].value_or(int64_t(2000)));
    cfg.iface.delete_bin_after_read = tbl["iface"]["delete_bin_after_read"].value_or(false);
    cfg.iface.flush_csv_per_segment = tbl["iface"]["flush_csv_per_segment"].value_or(true);

    if (cfg.source.empty())
        throw std::runtime_error("配置文件缺少 run.source 字段");
    if (cfg.types.empty())
        throw std::runtime_error("配置文件缺少 [[decode]] 类型定义");

    return cfg;
}
