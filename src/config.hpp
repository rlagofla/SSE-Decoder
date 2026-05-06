#pragma once
// config.hpp — TOML 配置文件解析

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <toml.hpp>

struct TypeConfig {
    uint32_t    hi;
    uint32_t    lo;
    std::string output;   // CSV 输出文件路径
    bool        dedup = true;
};

struct Config {
    std::string          mode      = "pcap";   // "pcap" 或 "iface"
    std::string          source;               // pcap 路径 或 网卡名
    uint16_t             port      = 5261;
    std::string          log_level = "info";   // trace/debug/info/warn/error
    std::vector<TypeConfig> types;
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
    cfg.port      = static_cast<uint16_t>(tbl["run"]["port"].value_or(int64_t(5261)));
    cfg.log_level = tbl["log"]["level"].value_or(std::string("info"));

    if (auto* arr = tbl["decode"].as_array()) {
        for (auto&& elem : *arr) {
            if (auto* t = elem.as_table()) {
                TypeConfig tc;
                tc.hi     = static_cast<uint32_t>((*t)["hi"].value_or(int64_t(0)));
                tc.lo     = static_cast<uint32_t>((*t)["lo"].value_or(int64_t(0)));
                tc.output = (*t)["output"].value_or(std::string(""));
                tc.dedup  = (*t)["dedup"].value_or(true);
                cfg.types.push_back(std::move(tc));
            }
        }
    }

    if (cfg.source.empty())
        throw std::runtime_error("配置文件缺少 run.source 字段");
    if (cfg.types.empty())
        throw std::runtime_error("配置文件缺少 [[decode]] 类型定义");

    return cfg;
}
