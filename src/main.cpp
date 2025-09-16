#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <thread>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <atomic>
#include <mutex>
#include "concurrentqueue.h"
#include <unordered_map>
#include <err.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>
#include <map>

#include "symboliser.h"

std::atomic<bool> stop_threading{false};

struct sample {
    uint64_t address;
    uint64_t ip;
};

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
    while (true) {
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
        PTRACE_O_TRACECLONE |  // new threads
        PTRACE_O_TRACEFORK  |  // fork()
        PTRACE_O_TRACEVFORK |  // vfork()
        PTRACE_O_EXITKILL) == -1){ // task exit
        perror("PTRACE_SETOPTIONS");
        exit(1);
    }    
}

static bool drain_samples(perf_event_mmap_page* metadata, moodycamel::ConcurrentQueue<struct sample>& sample_q, size_t page_size){
    uint64_t data_size = page_size * 8;
    uint64_t head = metadata->data_head;
    std::atomic_thread_fence(std::memory_order_acquire);
    uint64_t tail = metadata->data_tail;

    if (head - tail > data_size) {
        // Overrun occurred
        fprintf(stderr, "perf buffer overrun: lost samples\n");
    }

    char *data = ((char*)metadata) + page_size;
    bool drained_one = false;
    while (tail < head) {
        perf_event_header *event_hdr = (perf_event_header *)(data + (tail % data_size));
        if (event_hdr->size == 0 || event_hdr->size > data_size) {
            // corrupted or not yet written record
            break;
        }
        if (event_hdr->type == PERF_RECORD_SAMPLE) {
            uint64_t* sample_data = (uint64_t*)((char*)event_hdr + sizeof(perf_event_header));
            sample sam = {sample_data[1], sample_data[0]};
            sample_q.enqueue(sam);
            drained_one = true;
        }
        tail += event_hdr->size;
    }
    metadata->data_tail = tail;

    return drained_one;
}

static void drain_samples_loop(std::unordered_map<pid_t, struct perf_event_mmap_page*>& maps, moodycamel::ConcurrentQueue<struct sample>& sample_q, size_t page_size, std::mutex& map_mutex) {
    bool drained_one = true;
    while(!stop_threading || drained_one) {
        map_mutex.lock();
        drained_one = false;
        for(auto entry : maps){
            drained_one = drain_samples(entry.second, sample_q, page_size) || drained_one;
        }
        map_mutex.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
// Function to drain and process samples produces by drain_samples_loop
static void process_samples_loop(moodycamel::ConcurrentQueue<struct sample>& sample_q, std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>>& samples) {
    struct sample s;
    bool found = sample_q.try_dequeue(s);
    while(!stop_threading || found) {
        if(found){
            samples[s.address][s.ip]++;
        }
        found = sample_q.try_dequeue(s);
    }
}
static struct perf_event_mmap_page* track_thread(pid_t tid, struct perf_event_attr& pe) {
    int fd = perf_event_open(&pe, tid, -1, -1, 0);    
    if (fd == -1) {
        perror("thread perf_event_open");
    }
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t mmap_size = (1 + (1 << 8)) * page_size;
    // TODO, does this run out of space?
    void *mmap_base = mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmap_base == MAP_FAILED) {
        perror("mmap");
        close(fd);
    }
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1)
        err(EXIT_FAILURE, "PERF_EVENT_IOC_RESET");
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
        err(EXIT_FAILURE, "PERF_EVENT_IOC_ENABLE");
    return (perf_event_mmap_page*) mmap_base;
}

static void print_results(std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>>& samples, Symboliser& symboliser) {
    // addr, (ip, count)
    // std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>> merged;
    // for(auto sample :samples) {
    //     for(auto inner_map : sample) {
    //         for(auto entry : inner_map.second) {
    //             merged[inner_map.first][entry.first] += entry.second;
    //         }
    //     }
    // }

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
    std::cout << "Address\t\t Instruction\t\t Cache Misses\t File\n";
    std::cout << "---------------------------------------------------------------\n";
    for(auto& addr_entry: addr_counts){
        // Ignore smaller ones
        if(std::get<1>(addr_entry) <= 1) continue;
        std::cout << std::left << std::setw(41) << std::hex << std::showbase <<  std::get<0>(addr_entry)  << std::left 
        << std::setw(29) << std::dec << std::get<1>(addr_entry) << "\n";
        // std::cout << "Address 0x" << std::hex << std::get<0>(addr_entry) << " total " << std::dec <<  << " misses\n";
        for(auto& ip_entry: std::get<2>(addr_entry)){
            Symbol symbol = symboliser.symbol(ip_entry.first);
            std::cout << std::left << std::setw(17) << "" << std::left << std::setw(24) << std::hex
             << std::showbase << ip_entry.first << std::left << std::setw(16) << std::dec 
             << ip_entry.second << std::setw(16)  << symbol.file << ":" << symbol.line << ":" << symbol.column <<  std::endl;
        }
        std::cout << std::endl;
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
    ptrace(PTRACE_CONT, child, 0, 0);  
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
    
    // Stores samples waiting to be processed
    moodycamel::ConcurrentQueue<struct sample> sample_q;
    // Used to lock the maps
    std::mutex map_mutex;
    // address (ip, count)
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>> samples; 
    std::unordered_map<pid_t, struct perf_event_mmap_page*> maps = {{child, metadata}};
    int status = 0;
    // Drain samples in maps in another thread
    std::thread drain_sample_thread(drain_samples_loop, std::ref(maps), std::ref(sample_q), page_size, std::ref(map_mutex));
    std::thread process_sample_thread(process_samples_loop, std::ref(sample_q), std::ref(samples));
    while (true) {
        // Look at all threads/children
        pid_t r = waitpid(-1, &status, __WALL | WNOHANG);
        if (r == -1) {
            if (errno == EINTR) continue;
            perror("waitpid");
            break;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            continue;
        }
        // If our process has spawned a new thread we should also track it
        if (r > 0 && WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            unsigned int event = status >> 16;
            if (event == PTRACE_EVENT_CLONE) {
                map_mutex.lock();
                pid_t new_tid;
                ptrace(PTRACE_GETEVENTMSG, r, 0, &new_tid);
                struct perf_event_mmap_page* mmap = track_thread(new_tid, pe);
                maps[new_tid] = mmap;
                map_mutex.unlock();
            }
            else if (event == PTRACE_EVENT_EXIT) {
                // thread is about to exit
                unsigned long code;
                ptrace(PTRACE_GETEVENTMSG, r, 0, &code);

                // flush its samples one last time
                drain_samples(maps[r], sample_q, page_size);
                // Free resources
                munmap(maps[r], mmap_size);
            }
        }
        if (r > 0) {
            ptrace(PTRACE_CONT, r, 0, 0);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Tell the draining thread to finish draining and return
    stop_threading = true;
    drain_sample_thread.join();
    process_sample_thread.join();
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    close(fd);

    std::cout << "Collection complete\n" << std::endl;
    print_results(samples, symboliser);
    
    std::cout << samples.size() << std::endl;
    std::cout << "Profiling complete.\n";
    return 0;
}