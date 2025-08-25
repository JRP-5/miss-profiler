#include <vector>
#include <thread>
#include <chrono>
#include <iostream>
#include <cstring>

void myfunc() {
    printf("myfunc address: %p\n", (void*)myfunc);
}

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
    void* p = malloc(4096 * 1024);
    memset(p, 1, 4096 * 1024); 
    double acc = 0;
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    for(auto a: allocations){
        acc+= *allocations[0];
    }
    for (auto ptr : allocations) {
        delete[] ptr;
    }
    std::vector<int> v(1000);
    for (int i = 0; i < 1000; ++i)
        v[i] = i;

    std::cout << "Sum = " << v[10] + v[20] << std::endl;
    myfunc();
    // std::this_thread::sleep_for(std::chrono::milliseconds(10000));
    return 0;
}
