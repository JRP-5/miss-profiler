#include <iostream>
#include <random>

int main() {
    std::mt19937 gen(42);
    std::uniform_int_distribution<int> dist(0, 100);

    int sum = 0;
    for (long i = 0; i < 500'000'000; i++) {
        int x = dist(gen);
        if (x < 50) sum += 1; 
        else sum -= 1;
    }

    std::cout << "Final sum = " << sum << "\n";
}