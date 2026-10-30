#ifndef PROFILE_H
#define PROFILE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifndef VECTOR_BYTES
#define VECTOR_BYTES 514
#endif
#define PROFILE_COUNT 26

struct profile {
	const char *profile_id;
	const char *evidence_aliases;
	const char *kernel_releases;
	const char *distribution_id;
	const char *distribution_version;
	const char *package_name;
	const char *package_versions;
	const char *filesystem;
	const char *lsm_constraint;
	const char *target_path;
	const char *target_build_id;
	const char *baseline_sha256;
	const char *mutated_sha256;
	const char *backing_page_sha256;
	const char *package_query;
	const char *execution_mode;
	const char *tc_mode;
	const char *consumer_mode;
	const char *direct_io_mode;
	const char *recovery_mode;
	const char *allowed_launchers;
	const char *automatic_launchers;
	const char *recovery_artifact;
	const char *recovery_sha256;
	const char *distribution_suite;
	const char *allowed_supplementary_groups;

	uid_t expected_uid;
	gid_t expected_gid;
	uid_t target_uid;
	gid_t target_gid;
	mode_t target_mode;
	uint32_t tc_frame_length;
	uint64_t target_size;
	uint64_t target_offset;

	uint8_t flexible_identity;
	uint8_t check_supplementary_groups;
	uint8_t enabled;
	uint8_t allow_seccomp;

	uint8_t guard_before[16];
	uint8_t original_slice[8];
	uint8_t desired_slice[8];
	uint8_t guard_after[16];

	const char *success_message;

	uint8_t tc_frame[96];
	uint8_t mutation_vector[VECTOR_BYTES];
};

extern const struct profile compiled_profiles[PROFILE_COUNT];
extern const size_t compiled_profile_count;

#endif
