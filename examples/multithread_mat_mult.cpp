#include <vector>
#include <thread>
#include <iostream>

void multiply(const std::vector<std::vector<int>> &A,
              const std::vector<std::vector<int>> &B,
              std::vector<std::vector<int>> &C,
              int start, int end) {
    int N = A.size();
    for (int i = start; i < end; i++) {
        for (int j = 0; j < N; j++) {
            int sum = 0;
            for (int k = 0; k < N; k++) {
                sum += A[i][k] * B[k][j];
            }
            C[i][j] = sum;
        }
    }
}

int main() {
    const int N = 800;
    std::vector<std::vector<int>> A(N, std::vector<int>(N, 1));
    std::vector<std::vector<int>> B(N, std::vector<int>(N, 2));
    std::vector<std::vector<int>> C(N, std::vector<int>(N, 0));

    int num_threads = 4;
    std::vector<std::thread> threads;
    int chunk = N / num_threads;

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back(multiply, std::cref(A), std::cref(B), std::ref(C),
                             t * chunk, (t + 1) * chunk);
    }
    for (auto &th : threads) th.join();

    std::cout << "C[0][0] = " << C[0][0] << "\n";
}