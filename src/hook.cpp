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
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <cstring>
#include <unistd.h>

struct MemoryRegion {
    void* start;
    size_t size;
    uint64_t total_misses;
};
struct PerfRing {
    int fd;
    void* base;
    size_t buffer_size;
    uint64_t read_head = 0;
};
std::vector<MemoryRegion> allocations;
std::thread monitor_thread;
bool thread_started = false;
bool thread_off = false;

PerfRing setup_perf_event() {
    struct perf_event_attr pe{};
    pe.type = PERF_TYPE_HARDWARE;
    pe.config = PERF_COUNT_HW_CACHE_MISSES;
    pe.size = sizeof(pe);
    pe.sample_period = 100000; // lower = more frequent
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.precise_ip = 2;
    pe.wakeup_events = 1;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open");
        std::exit(1);
    }

    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t mmap_len = (1 + 8) * page_size; // 1 metadata + 8 pages buffer
    void* base = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        std::exit(1);
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    return PerfRing{fd, base, mmap_len - page_size};
}
void* find_allocation(void* addr) {
    for (auto& a : allocations) {
        if (addr >= a.start && addr < static_cast<char*>(a.start) + a.size) {
            a.total_misses++;
            return a.start;
        }
    }
    return nullptr;
}
int setup_perf_counter() {
    uint64_t val;
    struct perf_event_attr  pe;

    // Configure the event to count cache misses
    std::memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_COUNT_HW_CACHE_MISSES;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_INSTRUCTIONS;
    pe.disabled = 1;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) {
        std::cerr << "perf_event_open failed: " << strerror(errno) << "\n";
        return -1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    return fd;
}
void monitor_cache_misses(PerfRing ring) {
    auto* header = (perf_event_mmap_page*)ring.base;
    char* data = (char*)ring.base + sysconf(_SC_PAGESIZE);

    while (!thread_off) {
        uint64_t head = __atomic_load_n(&header->data_head, __ATOMIC_ACQUIRE);
        while (ring.read_head < head) {
            size_t offset = ring.read_head % ring.buffer_size;
            struct perf_event_header* eh = (struct perf_event_header*)(data + offset);
            if (eh->type == PERF_RECORD_SAMPLE) {
                uint64_t* sample_data = (uint64_t*)(eh + 1);
                uint64_t ip = *sample_data++;
                uint64_t addr = *sample_data++;

                void* matched = find_allocation((void*)addr);
                if (matched) {
                    fprintf(stderr, "[miss] addr: %p (in alloc: %p)\n", (void*)addr, matched);
                }
            }
            ring.read_head += eh->size;
        }
        header->data_tail = ring.read_head;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void dump_backtrace(){
    const auto MAX_SIZE = 64;
    std::vector<void *> trace(MAX_SIZE);
    const auto size = unw_backtrace(trace.data(), MAX_SIZE);
    trace.resize(size);
    for(auto ip: trace){
        fprintf(stderr, "\tip: %p\n", ip);
    }
    
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
        if(!thread_started){
            thread_started = true;
            PerfRing ring = setup_perf_event();
            monitor_thread = std::thread(monitor_cache_misses, ring);
        }
        void *ret = original_malloc_fn(size); 
        // Add the memory region to our list     
        allocations.push_back({ret, size, 0});
        dump_backtrace();
        fprintf(stderr, "malloc intercepted: %zu -> %p\n", size, ret);
        reentrant = false;
        
        return ret;
    }
}

int main() {
    return 0;
}