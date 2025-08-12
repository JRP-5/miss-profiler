
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <vector>

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                             int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
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

    // Parent process: attach profiler to child
    struct perf_event_attr pe{};
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HW_CACHE;
    pe.size = sizeof(pe);
    pe.config = (PERF_COUNT_HW_CACHE_LL) |
                (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
    pe.sample_period = 1000; // adjust for sampling rate
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_ADDR;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    pe.precise_ip = 2; // Request precise event if available

    int fd = perf_event_open(&pe, child, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open");
        return 1;
    }

    // Enable event
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // Optionally: mmap ring buffer for samples
    // struct perf_event_mmap_page *metadata = (perf_event_mmap_page*)mmap(...);

    // Wait for child to finish
    int status;
    waitpid(child, &status, 0);

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    close(fd);

    std::cout << "Profiling complete.\n";
    return 0;
}
