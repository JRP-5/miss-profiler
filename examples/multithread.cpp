#include <iostream>
#include <thread>
#include <atomic>
#include <vector>

std::atomic<int> counter(0);

void increment(int times) {
    for (int i = 0; i < times; i++) {
        counter.fetch_add(1, std::memory_order_relaxed);
    }
    std::vector<double*> allocations;
    for (int i = 0; i < 100; ++i) {
        double* data = new double[100000];
        allocations.push_back(data);
        for (int j = 0; j < 100000; j += 100) {
            data[j] += 1.0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
void spawn_threads() {
    const int numThreads = 4;
    const int incrementsPerThread = 100000;
    
    std::vector<std::thread> threads;
    // start some threads
    for (int i = 0; i < numThreads; i++) {
        threads.emplace_back(increment, incrementsPerThread);
    }

    // wait for them all to finish
    for (auto& t : threads) {
        t.join();
    }
}
int main() {
    std::thread th(spawn_threads);
    th.join();
    // spawn_threads();
    // std::cout << "Final counter value: " << counter.load() << "\n";

    return 0;
}