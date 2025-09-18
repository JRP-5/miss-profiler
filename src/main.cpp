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
#include <fstream>
#include <sstream>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <err.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>

#include "sample.hpp"

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

enum Event {
    CACHE_MISS,
    BRANCH_MISS
};

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [-e CACHE_MISS | BRANCH_MISS] <program> [args...]\n";
        return 1;
    }
    Event choice = CACHE_MISS; 
    int i = 1;
    while(i < argc-1){
        if(strcmp(argv[i],"-event") == 0 || strcmp(argv[i],"-e") == 0){
            if(strcmp(argv[i+1], "CACHE_MISS") == 0) {
                choice = CACHE_MISS;
            }
            else if(strcmp(argv[i+1], "BRANCH_MISS") == 0) {
                choice = BRANCH_MISS;
            }
            else {
                std::cerr << "Usage: " << argv[0] << " [-e CACHE_MISS | BRANCH_MISS] <program> [args...]\n";
                return 1;
            }
            i++;
        }
        else {
            std::cerr << "Usage: " << argv[0] << " [-e CACHE_MISS | BRANCH_MISS] <program> [args...]\n";
            return 1;
        }
        i++;
    }
        
    pid_t child = fork();
    if (child == 0) {
        // Child process: execute the target
        execvp(argv[argc-1], &argv[argc-1]);
        perror("execvp failed");
        _exit(1);
    }
    wait_exec_stop(child);                 
    Symboliser symboliser(child);           
    // Let the child continue
    ptrace(PTRACE_CONT, child, 0, 0);  
    struct perf_event_attr pe{};
    memset(&pe, 0, sizeof(pe));
    
    pe.size = sizeof(pe);
    pe.sample_period = 1000; // adjust for sampling rate
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.precise_ip = 2;
    switch(choice) {
        case CACHE_MISS:
            pe.type = PERF_TYPE_HW_CACHE;
            pe.config = PERF_COUNT_HW_CACHE_MISSES;
            pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
            break;
        case BRANCH_MISS:
            pe.type = PERF_TYPE_HARDWARE;
            pe.config = PERF_COUNT_HW_BRANCH_MISSES;
            pe.sample_type = PERF_SAMPLE_IP;
            break;
    }
    int fd = perf_event_open(&pe, child, -1, -1, 0);    
    if (fd == -1) {
        perror("perf_event_open");
        return 1;
    }

    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t mmap_size = (1 + (1 << 8)) * page_size;
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
    
    // Used to lock the maps
    std::mutex map_mutex;
    std::unique_ptr<SampleStore> sample_store;
    switch(choice) {
        case CACHE_MISS:
            sample_store = std::make_unique<CacheMissStore>();
            break;
        case BRANCH_MISS:
            sample_store = std::make_unique<BranchMissStore>();
            break;
    }
    std::unordered_map<pid_t, struct perf_event_mmap_page*> maps = {{child, metadata}};
    
    // Drain samples in maps in another thread    
    std::thread drain_sample_thread([&]{
        sample_store->drain_samples_loop(maps, page_size, map_mutex, stop_threading);
    });

    std::thread process_sample_thread([&]{
        sample_store->process_samples_loop(stop_threading);
    });
    
    int status = 0;
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
                sample_store->drain_samples(maps[r], page_size);
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
    sample_store->print_results(symboliser);

    std::cout << "Profiling complete.\n";
    return 0;
}