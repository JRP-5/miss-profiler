#include <vector>
#include <thread>
#include <chrono>
#include <iostream>

int main() {
    std::vector<double*> allocations;

    for (int i = 0; i < 100; ++i) {
        double* data = new double[100000];
        allocations.push_back(data);
        for (int j = 0; j < 100000; j += 100) {
            data[j] += 1.0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    double acc = 0;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    for(auto a: allocations){
        acc+= *allocations[0];
    }
    for (auto ptr : allocations) {
        delete[] ptr;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    return 0;
}
