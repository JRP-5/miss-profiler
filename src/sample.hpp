#include <unordered_map>
#include <cstdint>
#include <atomic>
#include <mutex>
#include "symboliser.h"
#include "concurrentqueue.h"

struct CacheMissSample {
    uint64_t addr, ip;
};
struct BranchMissSample {
    uint64_t ip;
};

struct SampleStore {
    virtual ~SampleStore() = default;
    virtual void print_results(Symboliser& symboliser, std::string file_name) const = 0;
    bool drain_samples(perf_event_mmap_page* metadata, size_t page_size);
    void drain_samples_loop(std::unordered_map<pid_t, struct perf_event_mmap_page*>& maps, size_t page_size, std::mutex& map_mutex, std::atomic<bool>& stop_threading);
    virtual void queueSamples(perf_event_header *event_hdr) = 0;
    virtual void process_samples_loop(std::atomic<bool>& stop_threading) = 0;
};
struct CacheMissStore : SampleStore {
    // address (ip, count)
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>> data;
    moodycamel::ConcurrentQueue<struct CacheMissSample> sample_q;
    void print_results(Symboliser& symboliser, std::string file_name) const override;
    void queueSamples(perf_event_header *event_hdr) override;
    void process_samples_loop(std::atomic<bool>& stop_threading) override;
};
struct BranchMissStore : SampleStore {
    // ip, count
    std::unordered_map<uint64_t, uint64_t> data;
    moodycamel::ConcurrentQueue<struct BranchMissSample> sample_q;
    void print_results(Symboliser& symboliser, std::string file_name) const override;
    void queueSamples(perf_event_header *event_hdr) override;
    void process_samples_loop(std::atomic<bool>& stop_threading) override;
};