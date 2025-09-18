#include <vector>
#include <tuple>
#include <ios>
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <linux/perf_event.h>
#include "concurrentqueue.h"

#include "sample.hpp"
 
void CacheMissStore::print_results(Symboliser& symboliser) const {
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
    std::cout << "Address\t\t Instruction\t\t Cache Misses\t File\n";
    std::cout << "---------------------------------------------------------------\n";
    for(auto& addr_entry: addr_counts){
        // Ignore smaller ones
        if(std::get<1>(addr_entry) <= 1) continue;
        std::cout << std::left << std::setw(41) << std::hex << std::showbase <<  std::get<0>(addr_entry)  << std::left 
        << std::setw(29) << std::dec << std::get<1>(addr_entry) << "\n";
        for(auto& ip_entry: std::get<2>(addr_entry)){
            Symbol symbol = symboliser.symbol(ip_entry.first);
            std::cout << std::left << std::setw(17) << "" << std::left << std::setw(24) << std::hex
            << std::showbase << ip_entry.first << std::left << std::setw(16) << std::dec 
            << ip_entry.second << std::setw(16)  << symbol.file << ":" << symbol.line << ":" << symbol.column <<  std::endl;
        }
        std::cout << std::endl;
    }
}

void CacheMissStore::queueSamples(perf_event_header *event_hdr) {
    uint64_t* sample_data = (uint64_t*)((char*)event_hdr + sizeof(perf_event_header));
    CacheMissSample sam = {sample_data[1], sample_data[0]};
    sample_q.enqueue(sam);
}

void BranchMissStore::print_results(Symboliser& symboliser) const {
    // ip, count
    std::vector<std::pair<uint64_t, uint64_t>> ip_counts;
    for(auto& entry : data){
        ip_counts.push_back({entry.first, entry.second});
    }
    std::sort(ip_counts.begin(), ip_counts.end(), [](std::pair<uint64_t, uint64_t> a, std::pair<uint64_t, uint64_t> b) {
        return a.second > b.second;
    });
    std::cout << "Instruction\t\t Branch Misses\t\t File\n";
    std::cout << "---------------------------------------------------------------\n";
    for(auto& entry: ip_counts){
        Symbol symbol = symboliser.symbol(entry.first);
        std::cout << std::left << std::setw(25) << std::hex << std::showbase <<  entry.first << std::left 
        << std::setw(24) << std::dec << entry.second << symbol.file << ":" << symbol.line << ":" << symbol.column <<  std::endl << "\n";
    }
}

void BranchMissStore::queueSamples(perf_event_header *event_hdr) {
    uint64_t ip = 0;
    std::memcpy(&ip, (char*)event_hdr + sizeof(perf_event_header), sizeof(ip));

    BranchMissSample sam{ ip };
    sample_q.enqueue(sam);
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

void SampleStore::drain_samples_loop(std::unordered_map<pid_t, struct perf_event_mmap_page*>& maps, size_t page_size, std::mutex& map_mutex, std::atomic<bool>& stop_threading) {
    bool drained_one = true;
    while(!stop_threading || drained_one) {
        map_mutex.lock();
        drained_one = false;
        for(auto entry : maps){
            drained_one = drain_samples(entry.second, page_size) || drained_one;
        }
        map_mutex.unlock();
    }
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