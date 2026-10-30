#!/bin/bash
set -e
CF="-O2 -Wall -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter -I."
gcc $CF -c -Dmain=nfq_helper_main nf_queue.c -o nf_queue.o
gcc $CF -c -Dmain=nft_helper_main nft-localout-queue.c -o nft.o
gcc $CF -c tc-netlink.c -o tc.o
gcc $CF -c launcher.c -o launcher.o
gcc $CF -c profile_registry.c -o profiles.o
gcc $CF -c runtime.c -o runtime.o
gcc -o zerofrag runtime.o launcher.o profiles.o nf_queue.o nft.o tc.o -lmnl -lcrypto
echo BUILD_OK
