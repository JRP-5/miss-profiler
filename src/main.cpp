#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <cstdint>
#include <thread>
#include <fstream>
#include <sstream>
#include <err.h>

#include "symboliser.h"

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                             int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

struct Sample {
    uint64_t ip;
    uint64_t addr;
};

// Stores an entry from the relevant /proc/<pid>/maps
struct MapEntry {
uint64_t start, end;
// std::string perms;
// std::string dev;
// uint64_t inode{};
// std::string path; // may be empty
};

static void process_samples(perf_event_mmap_page* metadata, std::vector<Sample>& samples, size_t page_size ){
    uint64_t data_size = page_size * 8;
    uint64_t head = metadata->data_head;
    uint64_t tail = metadata->data_tail;
    char *data = ((char*)metadata) + page_size;
    
    while (tail < head) {
        perf_event_header *event_hdr = (perf_event_header *)(data + (tail % data_size));
        if (event_hdr->type == PERF_RECORD_SAMPLE) {
            uint64_t* sample_data = (uint64_t*)((char*)event_hdr + sizeof(perf_event_header));
            Sample s;
            s.ip = sample_data[0];
            s.addr = sample_data[1];
            samples.push_back(s);
        }
        tail += event_hdr->size;
    }
    metadata->data_tail = tail;

}
static std::vector<MapEntry> attempt_read_proc_maps(pid_t pid){
    std::vector<MapEntry> out;
    std::string p = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream inFile(p);
    if (!inFile) return out;
    std::string line;
    while (std::getline(inFile, line)) {
        MapEntry e{};
        std::string addr;
        std::istringstream iss(line);
        iss >> addr;
        size_t dash = addr.find('-');
        e.start = std::strtoull(addr.substr(0, dash).c_str(), nullptr, 16);
        e.end = std::strtoull(addr.substr(dash+1).c_str(), nullptr, 16);
    //     e.offset= std::strtoull(offset.c_str(), nullptr, 16);
    //     std::string path;
    //     std::getline(iss, path);
    //     if (!path.empty() && path[0]==' ') path.erase(0,1);
    //     e.path = path;
        out.push_back(std::move(e));
    }
    return out;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program> [args...]\n";
        return 1;
    }

    pid_t child = fork();
    if (child == 0) {
        // Child process: execute the target
        execvp(argv[1], &argv[1]);
        perror("execvp failed");
        return 1;
    }

    // Parent: wait for /proc/<pid>/maps to appear and capture it (so we can symbolize later)
    std::vector<MapEntry> maps;
    for (int i = 0; i < 200; ++i) {
        maps = attempt_read_proc_maps(child);
        if (!maps.empty()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    if (maps.empty()) std::cerr << "Warning: failed to capture /proc/" << child << "/maps; symbols will be poor\n";      

    // Parent process: attach profiler to child
    struct perf_event_attr pe{};
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HW_CACHE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CACHE_MISSES;
    // pe.config = (PERF_COUNT_HW_CACHE_LL) |
    //             (PERF_COUNT_HW_CACHE_OP_READ << 8) |
    //             (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
    pe.sample_period = 1000; // adjust for sampling rate
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.precise_ip = 2;
    
    int fd = perf_event_open(&pe, child, -1, -1, 0);    
    if (fd == -1) {
        perror("perf_event_open");
        return 1;
    }

    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t mmap_size = (1 + 8) * page_size;
    void *mmap_base = mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    struct perf_event_mmap_page *metadata = (perf_event_mmap_page*) mmap_base;

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1)
        err(EXIT_FAILURE, "PERF_EVENT_IOC_RESET");
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
        err(EXIT_FAILURE, "PERF_EVENT_IOC_ENABLE");

    
    std::vector<Sample> samples; 
    samples.reserve(100000);
    int status = 0;
    bool child_running = true;
    
    while (child_running) {
        // poll-less periodic drain to keep buffer from overflowing but minimal work
        process_samples(metadata, samples, page_size);
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r) child_running = false;
        else std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    close(fd);

    std::cout << "Collection complete\n" << std::endl;
    Symboliser symboliser;
    for(auto a: samples){
        Symbol symbol = symboliser.symbol(a.ip);
        std::cout << symbol.name << std::endl;
        // std::cout << std::hex << a.ip << " " << a.addr << std::endl;
    }
    std::cout << samples.size() << std::endl;
    std::cout << "Profiling complete.\n";
    return 0;
}
