#pragma once

#include <atomic>
#include <string>

#include "config.hpp"
#include "pipeline.hpp"

int RunIfaceMode(const IfaceConfig& cfg, Pipeline& pipeline, uint16_t port_filter,
                 std::atomic<bool>& stop, std::string* err_msg);

int RunBinMode(const IfaceConfig& cfg, Pipeline& pipeline, uint16_t port_filter,
               std::atomic<bool>& stop, std::string* err_msg);
