#include <iostream>
#include <thread>
#include <vector>
#include <random>
#include <atomic>
#include <chrono>

// Worker function: estimate pi using Monte Carlo
void monte_carlo_pi(long long num_samples, std::atomic<long long> &inside_count, unsigned seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    long long local_count = 0;
    for (long long i = 0; i < num_samples; i++) {
        double x = dist(rng);
        double y = dist(rng);
        if (x * x + y * y <= 1.0)
            local_count++;
    }
    inside_count.fetch_add(local_count, std::memory_order_relaxed);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <num_threads> <samples_per_thread>\n";
        return 1;
    }

    int num_threads = std::stoi(argv[1]);
    long long samples_per_thread = std::stoll(argv[2]);

    std::atomic<long long> inside_count(0);
    std::vector<std::thread> threads;

    auto start = std::chrono::high_resolution_clock::now();

    // Launch threads
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back(monte_carlo_pi, samples_per_thread, std::ref(inside_count), i+1);
    }

    for (auto &t : threads)
        t.join();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    long long total_samples = num_threads * samples_per_thread;
    double pi_estimate = 4.0 * inside_count.load() / (double) total_samples;

    std::cout << "Threads: " << num_threads
              << " | Samples/thread: " << samples_per_thread
              << " | Pi ≈ " << pi_estimate
              << " | Time: " << elapsed.count() << "s\n";

    return 0;
}
