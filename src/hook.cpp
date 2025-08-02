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
#include <mutex>
#include <unistd.h>

#include "symboliser.h"

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
std::mutex alloc_mutex;
std::vector<MemoryRegion> allocations;
std::thread monitor_thread;
bool thread_started = false;
bool thread_off = false;
Symboliser symboliser;


constexpr int SAMPLE_FREQ = 10000;
constexpr size_t MMAP_DATA_SIZE = 1 << 12;  // 4KB
constexpr size_t MMAP_PAGE_COUNT = 1 + (MMAP_DATA_SIZE / 4096); // 1 metadata + N data


int setup_perf_event() {
    pid_t pid = getpid();
    fprintf(stderr, "PID: %d\n", pid);
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    // pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(perf_event_attr);
    // pe.config = PERF_COUNT_HW_CACHE_MISSES;
    pe.type = PERF_TYPE_RAW;
    pe.config = 0x01cd; // MEM_LOAD_RETIRED.L1_MISS
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
    // pe.sample_type |= PERF_SAMPLE_DATA_SRC;
    pe.freq = 1;
    pe.sample_freq = SAMPLE_FREQ;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.sample_id_all = 1;
    pe.wakeup_events = 1;
    // pe.type = PERF_TYPE_RAW;
    // pe.config = (0x01cd | (3ULL << 8));  // MEM_LOAD_RETIRED.L1_MISS + umask
    pe.precise_ip = 2;
    // pe.sample_type |= PERF_SAMPLE_DATA_SRC;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) {
        std::cerr << "Error opening perf event: " << strerror(errno) << std::endl;
        return -1;
    }

  

    return fd;
}

void dump_backtrace(){
    const auto MAX_SIZE = 64;
    std::vector<void *> trace(MAX_SIZE);
    const auto size = unw_backtrace(trace.data(), MAX_SIZE);
    trace.resize(size);
    for(auto ip: trace){
        uint64_t ip_ptr = reinterpret_cast<uint64_t>(ip);
        Symbol info = symboliser.symbol(ip_ptr);
        // fprintf(stderr, "%s %d %d\n", info.dso.c_str(), info.line, info.column);
        // fprintf(stderr, "%s\n", info.dso.c_str());
        // fprintf(stderr, "\tip: %p\n", ip);
    }
    
}
void* find_malloc_region(uint64_t addr, uint64_t ip) {
    uintptr_t miss_addr = reinterpret_cast<uintptr_t>(addr);
    uintptr_t page_size = sysconf(_SC_PAGESIZE);
    miss_addr &= ~(page_size - 1);
    std::cout << "[Miss] IP=0x" << std::hex << ip
          << "  ADDR=0x" << addr << std::dec << "\n";

    for (const auto& a : allocations) {
        auto start = reinterpret_cast<uintptr_t>(a.start);
        auto end = start + a.size;
        if (miss_addr >= start && miss_addr < end) {
            std::cout << "  --> Match: region " << a.start << " - " 
                    << (void*)end << " (size = " << a.size << ")\n";
        } else {
            // std::cout << "  (Checked: " << a.start << " - " 
            //         << (void*)end << ")\n";
        }
    }
    return 0;
}

void monitor_cache_misses() {
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    int fd = setup_perf_event();
    size_t mmap_size = (1 + 8) * 4096; 
    void* mmap_buf = mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_buf == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return;
    }

    auto* metadata = (perf_event_mmap_page*)mmap_buf;
    char* data = ((char*)mmap_buf) + 4096;

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    while (!thread_off) {       
        uint64_t data_head = metadata->data_head;
        __sync_synchronize();

        uint64_t data_tail = metadata->data_tail;   
        size_t size = data_head - data_tail;
        size_t offset = data_tail % (1<<12);    
        size_t bytes_read = 0;

        while (bytes_read < size) {
            // std::cout << "HERE" << std::endl;
            auto* hdr = (perf_event_header*)(data + offset);
            if (hdr->type == PERF_RECORD_SAMPLE) {
                uint64_t* sample_data = (uint64_t*)((char*)hdr + sizeof(perf_event_header));
                uint64_t ip = sample_data[0];
                uint64_t addr = sample_data[1];
                auto region = find_malloc_region(addr, ip);
                if(region){
                    std::cout << "[Cache Miss] IP= 0x" << std::hex << ip << "  ADDR= 0x" << addr << std::dec << "In region= "  << region << std::endl;
                }
                else{
                    std::cout << "[Cache Miss] IP= 0x" << std::hex << ip << "  ADDR= 0x" << addr << std::dec << std::endl;
                }
            }

            size_t hdr_sz = hdr->size;
            offset = (offset + hdr_sz) % (1<<12);
            bytes_read += hdr_sz;
        }

        metadata->data_tail = data_head;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    munmap(mmap_buf, mmap_size);
    close(fd);
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
            monitor_thread = std::thread(monitor_cache_misses);
        }
        void *ret = original_malloc_fn(size); 
        // Add the memory region to our list     
        allocations.push_back({ret, size, 0});

        // Get some information about the malloc call
        dump_backtrace();
        fprintf(stderr, "malloc intercepted: %zu -> %p\n", size, ret);
        reentrant = false;
        
        return ret;
    }
}
extern "C" void* __libc_malloc(size_t size); // fallback if needed

void* operator new(size_t size) {
    void* ptr = malloc(size); // reuses your existing hook
    return ptr;
}

void* operator new[](size_t size) {
    void* ptr = malloc(size); // reuses your existing hook
    return ptr;
}

void operator delete(void* ptr) noexcept {
    free(ptr); // optional
}

void operator delete[](void* ptr) noexcept {
    free(ptr); // optional
}
// __attribute__((constructor))
// static void setup() {
//     monitor_thread = std::thread(monitor_cache_misses);
//     thread_started = true;
// }
int main() {
    return 0;
}