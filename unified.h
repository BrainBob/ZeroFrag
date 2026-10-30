#ifndef UNIFIED_H
#define UNIFIED_H

#include <stdint.h>
#include <stddef.h>

/* Inherited file descriptors used across the userns transition. */
#define PROFILE_FD	3
#define SELF_FD		4
#define TARGET_FD	5
#define VECTOR_FD	6

/* Trigger packet geometry: 8 bytes of target file + 514-byte vector. */
#define TARGET_BYTES	8
#define VECTOR_BYTES	514
#define TOTAL_BYTES	(TARGET_BYTES + VECTOR_BYTES)

int nfq_helper_main(int argc, char **argv);
int nft_helper_main(void);
int tc_netlink_setup_88(const uint8_t *frame, size_t length);
int tc_netlink_setup_96(const uint8_t *frame, size_t length);

#endif
