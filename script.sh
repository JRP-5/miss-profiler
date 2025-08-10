ADDR_IN_FILE=$(printf  "%#X\n" $(( 0x58c42d479245 - 0x58c42d478000 )))
eu-addr2line -f -C -e ./bin/vector "$ADDR_IN_FILE"
sudo LD_PRELOAD=./lib/libhook.so ./bin/vector