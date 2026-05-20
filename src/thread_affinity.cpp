#include "thread_affinity.hpp"

#include <cstring>
#include <iostream>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

bool PinCurrentThreadToCpu(int cpu) {
    if (cpu < 0) return true;
    int n = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
    if (n <= 0 || cpu >= n) {
        std::cerr << "[affinity] invalid cpu " << cpu << " (online=" << n << "), skip pin\n";
        return false;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(static_cast<size_t>(cpu), &set);
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (rc != 0) {
        std::cerr << "[affinity] pthread_setaffinity_np cpu " << cpu << ": " << strerror(rc) << "\n";
        return false;
    }
    return true;
}
