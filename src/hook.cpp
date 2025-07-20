#include <dlfcn.h>
#include <cstdio>  // fprintf
#include <cassert> // assert
#include <cstdlib> // malloc
#include <vector>
#include <iostream>
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>
#include <thread>
#include <chrono>

std::thread monitor_thread;
void dump_backtrace(){
    const auto MAX_SIZE = 64;
    std::vector<void *> trace(MAX_SIZE);
    const auto size = unw_backtrace(trace.data(), MAX_SIZE);
    trace.resize(size);
    for(auto ip: trace){
        fprintf(stderr, "\tip: %p\n", ip);
    }
    
}
void monitor_cache_misses() {
    struct perf_event_attr pe{};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_CACHE_MISSES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open");
        return;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}
void monitor_loop() {
    while (true) {
        monitor_cache_misses(); 
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}
__attribute__((constructor))
static void on_load() {
    fprintf(stderr, "[memprofiler] Loaded via LD_PRELOAD\n");
    // Start background perf monitor
    monitor_thread = std::thread(monitor_loop);
}
extern "C"
{   
    void* malloc(size_t size)
    {
        static void* original_malloc = dlsym(RTLD_NEXT, "malloc");
        assert(original_malloc);
        auto *original_malloc_fn = reinterpret_cast<decltype(&::malloc)>(original_malloc);
        
        // Stop infinite recursion
        thread_local bool reentrant = false;
        if (reentrant) {
            return original_malloc_fn(size);
        }
        reentrant = true;

        void *ret = original_malloc_fn(size);        
        dump_backtrace();
        fprintf(stderr, "malloc intercepted: %zu -> %p\n", size, ret);
        reentrant = false;
        
        return ret;
    }
}

int main() {
    return 0;
}

__attribute__((destructor))
static void on_unload() {
    monitor_thread.join();
}