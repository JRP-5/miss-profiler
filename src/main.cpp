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
#include <algorithm>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <err.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>

#include "symboliser.h"

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                             int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void wait_exec_stop(pid_t pid) {
    // Attach without stopping threads immediately; request exec stops.
    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD) == -1) {
        perror("PTRACE_SEIZE");
        exit(1);
    }
    // Stop the child so we can get its symbols
    if (kill(pid, SIGSTOP) == -1) {
        perror("kill(SIGSTOP)");
        exit(1);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) { perror("waitpid initial"); exit(1); }

    // Let it run until the exec boundary.
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) { perror("PTRACE_CONT"); exit(1); }
    for (;;) {
        if (waitpid(pid, &status, 0) != pid) { perror("waitpid loop"); exit(1); }
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP) {
                unsigned long event = 0;
                if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &event) == -1) event = 0;
                // SIGTRAP with EXEC event means we're at exec stop.
                if ((status >> 16) == PTRACE_EVENT_EXEC) break;
            }
            // Pass other stops through.
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) { perror("PTRACE_CONT"); exit(1); }
        } else if (WIFEXITED(status) || WIFSIGNALED(status)) {
            fprintf(stderr, "Child exited before exec\n");
            exit(1);
        }
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, 0,
        // PTRACE_O_TRACECLONE |  // new threads
        // PTRACE_O_TRACEFORK  |  // fork()
        // PTRACE_O_TRACEVFORK |  // vfork()
        PTRACE_O_EXITKILL) == -1){ // task exit
        perror("PTRACE_SETOPTIONS");
        exit(1);
    }    
    // std::cout << "HERE\n";
}

static void process_samples(perf_event_mmap_page* metadata, std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>>& samples, size_t page_size ){
    uint64_t data_size = page_size * 8;
    uint64_t head = metadata->data_head;
    uint64_t tail = metadata->data_tail;
    char *data = ((char*)metadata) + page_size;
    
    while (tail < head) {
        perf_event_header *event_hdr = (perf_event_header *)(data + (tail % data_size));
        if (event_hdr->type == PERF_RECORD_SAMPLE) {
            uint64_t* sample_data = (uint64_t*)((char*)event_hdr + sizeof(perf_event_header));
            samples[sample_data[1]][sample_data[0]]++;
        }
        tail += event_hdr->size;
    }
    metadata->data_tail = tail;

}

static void track_thread(unsigned long tid, struct perf_event_attr& pe) {
    int fd = perf_event_open(&pe, tid, -1, -1, 0);    
    if (fd == -1) {
        perror("child perf_event_open");
    }
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t mmap_size = (1 + (1 << 8)) * page_size;
    // TODO, does this run out of space?
    void *mmap_base = mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
    }
}
static int module_callback(Dwfl_Module* m, void**, const char* name,
                           Dwarf_Addr low, void* ) {
    Dwarf_Addr start = 0;
    const char* path = dwfl_module_info(m, nullptr, &start, nullptr,
                                        nullptr, nullptr, nullptr, nullptr);
    std::cerr << "[DWFL] " << (name ? name : "(anon)") << " -> "
              << (path ? path : "(no-path)")
              << " @ 0x" << std::hex << start << std::dec << "\n";
    return DWARF_CB_OK;
}
static void print_results(std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>>& samples, Symboliser& symboliser) {
    // Addr, total count, (ip, count) 
    std::vector<std::tuple<uint64_t, uint64_t, std::vector<std::pair<uint64_t, uint64_t>>>> addr_counts;
    for(auto inner_map : samples){
        std::tuple<uint64_t, uint64_t, std::vector<std::pair<uint64_t, uint64_t>>> output = {inner_map.first, 0, {}};
        for(auto entry : inner_map.second){
            std::get<1>(output) += entry.second;
            std::get<2>(output).push_back(std::make_pair(entry.first, entry.second));
        }
        std::sort(std::get<2>(output).begin(), std::get<2>(output).end(), [](std::pair<uint64_t, uint64_t> a, std::pair<uint64_t, uint64_t> b) {
            return a.second > b.second;
        });
        addr_counts.push_back(output);
    }
    std::sort(addr_counts.begin(), addr_counts.end(), [](std::tuple<uint64_t, uint64_t, std::vector<std::pair<uint64_t, uint64_t>>> a, std::tuple<uint64_t, uint64_t, std::vector<std::pair<uint64_t, uint64_t>>> b) {
        return std::get<1>(a) > std::get<1>(b);
    });
    for(auto& addr_entry: addr_counts){
        if(std::get<1>(addr_entry) <= 1) continue;
        std::cout << "Address 0x" << std::hex << std::get<0>(addr_entry) << " total " << std::dec << std::get<1>(addr_entry) << " misses\n";
        for(auto& ip_entry: std::get<2>(addr_entry)){
            Symbol symbol = symboliser.symbol(ip_entry.first);
             std::cout << "\tIP 0x" << std::hex << ip_entry.first
                      << " : " << std::dec << ip_entry.second << " misses\n\tFunction: " << symbol.name << "\n\tFile: " << symbol.file << ":" << symbol.line << ":" << symbol.column <<  std::endl;
        }
    }
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
        _exit(1);
    }
    wait_exec_stop(child);                 
    Symboliser symboliser(child);           
    // Let the child continue
    ptrace(PTRACE_DETACH, child, 0, 0);  
    struct perf_event_attr pe{};
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HW_CACHE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CACHE_MISSES;
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
    size_t mmap_size = (1 + (1 << 8)) * page_size;
    // TODO, does this run out of space?
    void *mmap_base = mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    struct perf_event_mmap_page *metadata = (perf_event_mmap_page*) mmap_base;

    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1)
        err(EXIT_FAILURE, "PERF_EVENT_IOC_RESET");
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
        err(EXIT_FAILURE, "PERF_EVENT_IOC_ENABLE");
    
    // addr, (ip, count)
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>> samples; 
    int status = 0;
    bool child_running = true;
    
    while (child_running) {
        // poll-less periodic drain to keep buffer from overflowing but minimal work
        process_samples(metadata, samples, page_size);
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) child_running = false;
        else std::this_thread::sleep_for(std::chrono::milliseconds(10));
        // If our process has spawned a new thread we should also track it
        if (status >> 16 == PTRACE_EVENT_CLONE) {
            unsigned long new_tid;
            ptrace(PTRACE_GETEVENTMSG, child, 0, &new_tid);
        }
        
    }
    
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    close(fd);

    std::cout << "Collection complete\n" << std::endl;
    
    print_results(samples, symboliser);
    std::cout << samples.size() << std::endl;
    std::cout << "Profiling complete.\n";
    return 0;
}