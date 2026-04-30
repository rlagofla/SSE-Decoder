#pragma once
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

template<typename T>
T from_string(const std::string& s) {
    std::stringstream ss(s);
    T value;
    ss >> value;
    return value;
}

// 简单拆分一行（不处理引号包裹的逗号）
std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream ss(line);
    std::string field;
    while (std::getline(ss, field, ',')) {
        fields.push_back(field);
    }
    return fields;
}

template<typename T>
std::vector<T> read_csv(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }

    std::vector<T> result;
    std::string line;
    bool first_line = true;
    while (std::getline(file, line)) {
        // 常见习惯：跳过标题行（如果你愿意，可以把这个行为做成参数）
        if (first_line) {
            first_line = false;
            continue;
        }
        if (line.empty()) continue;

        auto fields = split_csv_line(line);
        // 调用 T 的静态工厂方法
        result.push_back(T::from_row(fields));
    }
    return result;
}