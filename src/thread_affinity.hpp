#pragma once
// cpu < 0 表示不绑定；失败时打印警告并返回 false
bool PinCurrentThreadToCpu(int cpu);
