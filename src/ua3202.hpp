#pragma once
// ua3202.hpp — MessageType UA3202 L2 全量快照（FAST+ZIP，占位）
//
// 每帧多支证券：5 价格 + 10 档买卖盘 + 近 N 笔成交。
// 字段布局尚未完整逆向，Parser/emit 待实现后在 pipeline.hpp 的 switch 里补充。

namespace ua3202 {

// struct Msg   { ... };  // TODO
// class  Parser { ... }; // TODO
// void   emit(...);      // TODO

}  // namespace ua3202
