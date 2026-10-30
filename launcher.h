#ifndef LAUNCHER_H
#define LAUNCHER_H

#define LAUNCHER_COUNT 19

struct launcher_backend {
	const char *name;
	const char *executable;
	const char *lsm_constraint;
	int kind;
	int enabled;
};

extern const struct launcher_backend launcher_backends[LAUNCHER_COUNT];

const struct launcher_backend *launcher_find(const char *name);
int launcher_installed(const struct launcher_backend *backend);
int launcher_run(const struct launcher_backend *backend, const char *self,
		 const char *stage, const char *suite);

#endif
