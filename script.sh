#LD_PRELOAD=./lib/libhook.so ./bin/vector 
# printf  "%#X\n" $(( 0x5ae5c21302a5 - 0x5ae5c212c000 ))
ADDR_IN_FILE=$(printf  "%#X\n" $(( 0x5ab1f6dd62a5 - 0x5ab1f6dd2000 )))
addr2line -f -p -C -e ./bin/vector "$ADDR_IN_FILE" 