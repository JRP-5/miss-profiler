#include <dlfcn.h>
#include <cstdio>  // fprintf
#include <cassert> // assert
#include <cstdlib> // malloc
#include <vector>
#include <iostream>
#define UNW_LOCAL_ONLY
#include <libunwind.h>

void backtrace(){
    fprintf(stderr, "backtracing");
    const auto MAX_SIZE = 64;
    fprintf(stderr, "0");
    std::vector<void *> trace(MAX_SIZE);
    fprintf(stderr, "1");
    const auto size = unw_backtrace(trace.data(), MAX_SIZE);
    fprintf(stderr, "2");
    trace.resize(size);
    fprintf(stderr, "done");
    for(auto ip: trace){
        fprintf(stderr, "\tip: %p\n", ip);
    }
    
}

extern "C"
{   
    void* malloc(size_t size)
    {
        static void* original_malloc = dlsym(RTLD_NEXT, "malloc");
        assert(original_malloc);
        auto *original_malloc_fn = reinterpret_cast<decltype(&::malloc)>(original_malloc);
        
        thread_local bool reentrant = false;
        if (reentrant) {
            return original_malloc_fn(size);
        }
        reentrant = true;


        void *ret = original_malloc_fn(size);
        
        backtrace();
        
        fprintf(stderr, "malloc intercepted: %zu -> %p\n", size, ret);
        reentrant = false;
        return ret;
    }
}