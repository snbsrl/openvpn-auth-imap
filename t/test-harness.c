/*
 * test-harness.c - load an OpenVPN auth plugin and drive it the way the
 * OpenVPN server does, without needing a running VPN.
 *
 * Usage:
 *   test-harness --plugin ./plugin.so --user U --pass P
 *                [--sync] [--count N] [--wait SECONDS] [--env K=V]...
 *                -- [plugin args...]
 *
 * Output: one line per attempt, "<n> ACCEPT|REJECT|TIMEOUT".
 * Exit:   0 all accepted, 1 any rejected, 2 plugin open failed,
 *         3 timeout or harness error.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openvpn-plugin.h>

#define MAX_ARGS  64
#define MAX_COUNT 64

enum { R_PENDING, R_ACCEPT, R_REJECT, R_TIMEOUT };
static const char *rname[] = { "PENDING", "ACCEPT", "REJECT", "TIMEOUT" };

static void h_vlog(openvpn_plugin_log_flags_t flags, const char *name,
                   const char *fmt, va_list ap)
{
    fprintf(stderr, "[%s]%s ", name,
            (flags & PLOG_ERR) ? " ERROR:" : (flags & PLOG_WARN) ? " WARN:" : "");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

static void h_log(openvpn_plugin_log_flags_t flags, const char *name,
                  const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    h_vlog(flags, name, fmt, ap);
    va_end(ap);
}

static void usage(void)
{
    fprintf(stderr, "usage: test-harness --plugin SO --user U --pass P "
            "[--sync] [--count N] [--wait S] [--env K=V]... -- [args]\n");
    exit(3);
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static char *xasprintf(const char *fmt, ...)
{
    va_list ap;
    char *s;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    s = malloc((size_t)n + 1);
    if (!s)
        exit(3);
    va_start(ap, fmt);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return s;
}

int main(int argc, char **argv)
{
    const char *plugin = NULL, *user = NULL, *pass = NULL;
    const char *extra_env[MAX_ARGS];
    const char *pargv[MAX_ARGS + 2];
    int nextra = 0, npargs = 0, sync = 0, count = 1, rc = 0;
    double wait_s = 30;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) {
            i++;
            break;
        } else if (!strcmp(argv[i], "--plugin") && i + 1 < argc) {
            plugin = argv[++i];
        } else if (!strcmp(argv[i], "--user") && i + 1 < argc) {
            user = argv[++i];
        } else if (!strcmp(argv[i], "--pass") && i + 1 < argc) {
            pass = argv[++i];
        } else if (!strcmp(argv[i], "--count") && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--wait") && i + 1 < argc) {
            wait_s = atof(argv[++i]);
        } else if (!strcmp(argv[i], "--env") && i + 1 < argc) {
            if (nextra < MAX_ARGS)
                extra_env[nextra++] = argv[++i];
        } else if (!strcmp(argv[i], "--sync")) {
            sync = 1;
        } else {
            usage();
        }
    }
    if (!plugin || !user || !pass || count < 1 || count > MAX_COUNT)
        usage();

    pargv[npargs++] = plugin;
    for (; i < argc && npargs <= MAX_ARGS; i++)
        pargv[npargs++] = argv[i];
    pargv[npargs] = NULL;

    void *dl = dlopen(plugin, RTLD_NOW);
    if (!dl) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }

    int (*open_v3)(int, struct openvpn_plugin_args_open_in const *,
                   struct openvpn_plugin_args_open_return *);
    int (*func_v3)(int, struct openvpn_plugin_args_func_in const *,
                   struct openvpn_plugin_args_func_return *);
    void (*close_v1)(openvpn_plugin_handle_t);

    *(void **)&open_v3  = dlsym(dl, "openvpn_plugin_open_v3");
    *(void **)&func_v3  = dlsym(dl, "openvpn_plugin_func_v3");
    *(void **)&close_v1 = dlsym(dl, "openvpn_plugin_close_v1");
    if (!open_v3 || !func_v3 || !close_v1) {
        fprintf(stderr, "plugin is missing v3 entry points\n");
        return 3;
    }

    struct openvpn_plugin_callbacks cb = {
        .plugin_log = h_log,
        .plugin_vlog = h_vlog,
    };
    const char *empty_env[] = { NULL };
    struct openvpn_plugin_args_open_in oin = {
        .type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY),
        .argv = pargv,
        .envp = empty_env,
        .callbacks = &cb,
        .ovpn_version = "harness",
    };
    struct openvpn_plugin_args_open_return oret = { 0 };

    if (open_v3(OPENVPN_PLUGINv3_STRUCTVER, &oin, &oret)
        != OPENVPN_PLUGIN_FUNC_SUCCESS) {
        printf("OPEN_FAILED\n");
        return 2;
    }
    if (!(oret.type_mask &
          OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY))) {
        fprintf(stderr, "plugin did not register AUTH_USER_PASS_VERIFY\n");
        return 3;
    }

    char tmpdir[] = "/tmp/ovpn-harness-XXXXXX";
    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return 3;
    }

    int result[MAX_COUNT];
    char *acf[MAX_COUNT];
    const char *fargv[] = { plugin, NULL };

    /* Fire all attempts first, so several are in flight at once. */
    for (int n = 0; n < count; n++) {
        const char *env[MAX_ARGS + 8];
        int ne = 0;
        char *u = xasprintf("username=%s", user);
        char *p = xasprintf("password=%s", pass);

        acf[n] = xasprintf("%s/acf.%d", tmpdir, n);
        /* OpenVPN creates the (empty) control file before the call. */
        if (!sync) {
            FILE *cf = fopen(acf[n], "w");
            if (cf)
                fclose(cf);
        }
        char *a = xasprintf("auth_control_file=%s", acf[n]);

        env[ne++] = u;
        env[ne++] = p;
        env[ne++] = "untrusted_ip=127.0.0.1";
        if (!sync)
            env[ne++] = a;
        for (int k = 0; k < nextra; k++)
            env[ne++] = extra_env[k];
        env[ne] = NULL;

        struct openvpn_plugin_args_func_in fin = {
            .type = OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY,
            .argv = fargv,
            .envp = env,
            .handle = oret.handle,
        };
        struct openvpn_plugin_args_func_return fret = { 0 };

        int r = func_v3(OPENVPN_PLUGINv3_STRUCTVER, &fin, &fret);
        result[n] = r == OPENVPN_PLUGIN_FUNC_SUCCESS  ? R_ACCEPT
                  : r == OPENVPN_PLUGIN_FUNC_DEFERRED ? R_PENDING
                  : R_REJECT;
        if (r == OPENVPN_PLUGIN_FUNC_DEFERRED && sync) {
            fprintf(stderr, "plugin deferred without auth_control_file\n");
            result[n] = R_TIMEOUT;
        }
        free(u);
        free(p);
        free(a);
    }

    /* Poll the auth control files like OpenVPN does. */
    double deadline = now() + wait_s;
    for (;;) {
        int pending = 0;
        for (int n = 0; n < count; n++) {
            if (result[n] != R_PENDING)
                continue;
            FILE *f = fopen(acf[n], "r");
            int c = f ? fgetc(f) : EOF;
            if (f)
                fclose(f);
            if (c == '1')
                result[n] = R_ACCEPT;
            else if (c == '0')
                result[n] = R_REJECT;
            else
                pending++;
        }
        if (!pending)
            break;
        if (now() > deadline) {
            for (int n = 0; n < count; n++)
                if (result[n] == R_PENDING)
                    result[n] = R_TIMEOUT;
            break;
        }
        nanosleep(&(struct timespec){ .tv_sec = 0, .tv_nsec = 20000000 }, NULL);
    }

    for (int n = 0; n < count; n++) {
        printf("%d %s\n", n, rname[result[n]]);
        if (result[n] == R_TIMEOUT)
            rc = 3;
        else if (result[n] == R_REJECT && rc == 0)
            rc = 1;
        unlink(acf[n]);
        free(acf[n]);
    }
    rmdir(tmpdir);

    close_v1(oret.handle);
    dlclose(dl);
    return rc;
}
