# An instruction level cache miss & branch misprediction profiler

```
mkdir build && cd build
cmake ..
make
```

Usage: 
```
./bin/main [OPTION] <program> [args ..]

The following options are available
    -e, --event           CACHE_MISS, BRANCH_MISS
    -o  --output          Name of the output file
```

Some example programs are available in `examples`