#include <vector>
#include <tuple>
#include <ios>
#include <iostream>
#include <fstream>  
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <linux/perf_event.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <err.h>
#include "concurrentqueue.h"

#include "sample.hpp"

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                             int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
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
void CacheMissStore::print_results(Symboliser& symboliser, std::string file_name) const {
    // Addr, total count, (ip, count)
    std::vector<std::tuple<uint64_t, uint64_t, std::vector<std::pair<uint64_t, uint64_t>>>> addr_counts;
    for(auto inner_map : data){
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
    std::ofstream out_file;
    out_file.open(file_name);
    out_file << "Address\t\t\t Instruction\t\t\t Cache Misses\t File\n";
    out_file << "---------------------------------------------------------------\n";
    for(auto& addr_entry: addr_counts){
        // Ignore smaller ones
        if(std::get<1>(addr_entry) <= 1) continue;
        out_file << std::left << std::setw(41) << std::hex << std::showbase <<  std::get<0>(addr_entry)  << std::left 
        << std::setw(29) << std::dec << std::get<1>(addr_entry) << "\n";
        for(auto& ip_entry: std::get<2>(addr_entry)){
            Symbol symbol = symboliser.symbol(ip_entry.first);
            out_file << std::left << std::setw(17) << "" << std::left << std::setw(24) << std::hex
            << std::showbase << ip_entry.first << std::left << std::setw(16) << std::dec 
            << ip_entry.second << std::setw(16)  << symbol.file << ":" << symbol.line << ":" << symbol.column <<  std::endl;
        }
        out_file << std::endl;
    }
    out_file.close();
}

void CacheMissStore::queueSamples(perf_event_header *event_hdr) {
    uint64_t* sample_data = (uint64_t*)((char*)event_hdr + sizeof(perf_event_header));
    CacheMissSample sam = {sample_data[1], sample_data[0]};
    sample_q.enqueue(sam);
}

void BranchMissStore::print_results(Symboliser& symboliser, std::string file_name) const {
    // ip, count
    std::vector<std::pair<uint64_t, uint64_t>> ip_counts;
    for(auto& entry : data){
        ip_counts.push_back({entry.first, entry.second});
    }
    std::sort(ip_counts.begin(), ip_counts.end(), [](std::pair<uint64_t, uint64_t> a, std::pair<uint64_t, uint64_t> b) {
        return a.second > b.second;
    });
    std::ofstream out_file;
    out_file.open(file_name);
    out_file << "Instruction\t\t\t Branch Misses\t\t File\n";
    out_file << "---------------------------------------------------------------\n";
    for(auto& entry: ip_counts){
        Symbol symbol = symboliser.symbol(entry.first);
        out_file << std::left << std::setw(25) << std::hex << std::showbase <<  entry.first << std::left 
        << std::setw(24) << std::dec << entry.second << symbol.file << ":" << symbol.line << ":" << symbol.column <<  std::endl << "\n";
    }
    out_file.close();
}

void BranchMissStore::queueSamples(perf_event_header *event_hdr) {
    uint64_t ip = 0;
    std::memcpy(&ip, (char*)event_hdr + sizeof(perf_event_header), sizeof(ip));

    BranchMissSample sam{ ip };
    sample_q.enqueue(sam);
}

SampleStore::SampleStore(struct perf_event_attr& pea) : pe(pea) {};

void SampleStore::queue_thread(pid_t r){
    thread_q.enqueue(r);
}
bool SampleStore::drain_samples(perf_event_mmap_page* metadata, size_t page_size){
    uint64_t data_size = page_size * 8;
    uint64_t head = metadata->data_head;
    std::atomic_thread_fence(std::memory_order_acquire);
    uint64_t tail = metadata->data_tail;

    // if (head - tail > data_size) {
    //     // Overrun occurred
    //     fprintf(stderr, "perf buffer overrun: lost samples\n");
    // }

    char *data = ((char*)metadata) + page_size;
    bool drained_one = false;
    while (tail < head) {
        perf_event_header *event_hdr = (perf_event_header *)(data + (tail % data_size));
        if (event_hdr->size == 0 || event_hdr->size > data_size) {
            // corrupted or not yet written record
            break;
        }
        if (event_hdr->type == PERF_RECORD_SAMPLE) {
            queueSamples(event_hdr);
            drained_one = true;
        }
        tail += event_hdr->size;
    }
    metadata->data_tail = tail;

    return drained_one;
}
void SampleStore::drain_samples_thread(std::vector<struct perf_event_mmap_page*>& maps, size_t page_size, std::mutex& map_mutex, std::atomic<bool>& stop_threading){
    bool drained_one = true;
    size_t local_idx = 0;
    while (!stop_threading || drained_one) {
        drained_one = false;
        perf_event_mmap_page* buf = nullptr;
        {
            std::lock_guard<std::mutex> lock(map_mutex);
            if (!maps.empty()) {
                buf = maps[local_idx % maps.size()];
                local_idx++;
            }
        }

        if (buf) {
            bool got = drain_samples(buf, page_size);
            drained_one = drained_one || got;
            if (!got) {
                // avoid busy spin when no samples
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        } else {
            // no buffers yet
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void SampleStore::drain_samples_pool(std::vector<struct perf_event_mmap_page*>& maps, size_t page_size, std::mutex& map_mutex, std::atomic<bool>& stop_threading) {
    size_t num_workers = std::thread::hardware_concurrency();
    num_workers = 1;
    if (num_workers == 0) num_workers = 4; // fallback
    
    // Create and launch our pool of threads
    std::vector<std::thread> workers;
    for (size_t i = 0; i < num_workers; i++) {
        workers.emplace_back([&]{
            drain_samples_thread(maps, page_size, map_mutex, stop_threading);
        });
    }
    
    while(!stop_threading){
        pid_t r;
        bool found = thread_q.try_dequeue(r);
        if(found){    
            pid_t new_tid;
            ptrace(PTRACE_GETEVENTMSG, r, 0, &new_tid);
            struct perf_event_mmap_page* mmap = track_thread(new_tid, pe);
            {
                std::lock_guard<std::mutex> lock(map_mutex);
                maps.push_back(mmap);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    for (auto& t : workers) t.join();
}

// Drains and process samples produces by drain_samples_loop
void CacheMissStore::process_samples_loop(std::atomic<bool>& stop_threading) {
    struct CacheMissSample s;
    bool found = sample_q.try_dequeue(s);
    while(!stop_threading || found) {
        if(found){
            data[s.addr][s.ip]++;
        }
        found = sample_q.try_dequeue(s);
    }
}

void BranchMissStore::process_samples_loop(std::atomic<bool>& stop_threading) {
    struct BranchMissSample s;
    bool found = sample_q.try_dequeue(s);
    while(!stop_threading || found) {
        if(found){
            data[s.ip]++;
        }
        found = sample_q.try_dequeue(s);
    }
}