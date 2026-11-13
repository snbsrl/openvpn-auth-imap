/*
 * openvpn-auth-imap.c
 *
 * OpenVPN plugin that authenticates users (auth-user-pass) by logging in
 * to one or more IMAP servers with the supplied username and password.
 *
 *  - Uses libcurl for IMAP, IMAPS and STARTTLS (handles quoting of
 *    credentials, SASL mechanisms and certificate verification).
 *  - Uses OpenVPN deferred authentication: the check runs in a detached
 *    process, so a slow IMAP server never blocks the OpenVPN event loop.
 *  - Several servers can be configured, tried in order.
 *
 * Plugin arguments (key=value), given on the "plugin" line:
 *   server=<url>       IMAP server, repeatable (up to 16), required:
 *                        imaps://host[:port]      implicit TLS (default 993)
 *                        starttls://host[:port]   STARTTLS     (default 143)
 *                        imap://host[:port]       clear text   (default 143)
 *                      IPv6 literals go in brackets: imaps://[2001:db8::1]
 *   policy=failover|any
 *                      failover (default): try the next server only if the
 *                        current one cannot be reached or errors; a
 *                        definite "wrong password" rejects immediately.
 *                      any: accept if any server accepts the credentials.
 *   cafile=<path>      CA bundle used to verify server certificates
 *   verify=0|1         verify server certificates (default 1)
 *   domain=<domain>    append "@domain" to usernames that have no '@'
 *   timeout=<seconds>  time allowed per server (default 10)
 *   match-cert=0|1     require the login to match the client certificate's
 *                      common_name (default 0, see below)
 *   cert-map=<file>    exceptions for match-cert: certificates whose
 *                      common_name differs from the IMAP user
 *
 * match-cert: the login name (after domain=) must equal the certificate's
 * common_name (also after domain=), compared case-insensitively. A login
 * that does not match is rejected before any IMAP server is contacted.
 * Which certificate field OpenVPN reports as common_name is chosen with
 * OpenVPN's x509-username-field option.
 *
 * cert-map file: one "<common_name> <imap-user>" pair per line; the user
 * is the last whitespace-separated field, so common names may contain
 * spaces. Repeat a common name to allow several users. A common name that
 * appears in the map may log in only as its mapped users; names not in the
 * map use the direct comparison. Blank lines and lines starting with '#'
 * are ignored. The file is read once at startup.
 *
 * License: MIT
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openvpn-plugin.h>

#define PLUGIN_NAME  "auth-imap"
#define MAX_USER_LEN 256
#define MAX_PASS_LEN 1024
#define MAX_SERVERS  16
#define MAX_HOST_LEN 253
#define MAX_CN_LEN   256
#define MAX_LOGIN_LEN (MAX_USER_LEN + MAX_HOST_LEN + 2)

enum tls_mode { MODE_IMAPS, MODE_STARTTLS, MODE_NONE };
enum policy   { POLICY_FAILOVER, POLICY_ANY };

/* Result of one authentication attempt. */
enum auth_result { AUTH_ERROR = -1, AUTH_REJECT = 0, AUTH_ACCEPT = 1 };

struct imap_server {
    char *spec;         /* normalised URL, used in log messages */
    char *host;
    int port;
    enum tls_mode mode;
};

struct cert_map_entry {
    char *cn;
    char *user;
};

struct plugin_ctx {
    struct imap_server servers[MAX_SERVERS];
    int nservers;
    enum policy policy;
    char *cafile;
    char *domain;
    long timeout;
    int verify;
    int match_cert;
    char *cert_map_path;
    struct cert_map_entry *cert_map;
    size_t cert_map_len;
    plugin_log_t log;
};

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static const char *get_env(const char *name, const char **envp)
{
    size_t len = strlen(name);

    if (!envp)
        return NULL;
    for (int i = 0; envp[i]; i++) {
        if (strncmp(envp[i], name, len) == 0 && envp[i][len] == '=')
            return envp[i] + len + 1;
    }
    return NULL;
}

/* Reject empty, overlong or control-character-laden input. */
static int valid_credential(const char *s, size_t maxlen)
{
    size_t n = 0;

    if (!s || !*s)
        return 0;
    for (; s[n]; n++) {
        unsigned char c = (unsigned char)s[n];
        if (c < 0x20 || c == 0x7f || n >= maxlen)
            return 0;
    }
    return 1;
}

/* Hostname, IPv4 or IPv6 literal: letters, digits, '.', '-', '_', ':' */
static int valid_host(const char *h)
{
    size_t n = 0;

    if (!h || !*h)
        return 0;
    for (; h[n]; n++) {
        char c = h[n];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' ||
              c == '_' || c == ':') || n >= MAX_HOST_LEN)
            return 0;
    }
    return 1;
}

static int parse_port(const char *s, int *out)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < 1 || v > 65535)
        return 0;
    *out = (int)v;
    return 1;
}

static const char *mode_name(enum tls_mode m)
{
    return m == MODE_IMAPS ? "imaps" : m == MODE_STARTTLS ? "starttls" : "imap";
}

static int default_port_for(enum tls_mode m)
{
    return m == MODE_IMAPS ? 993 : 143;
}

/*
 * Parse "scheme://host[:port][/]" where host may be "[IPv6]".
 * The scheme is required. Returns 1 on success, 0 on a syntax error.
 */
static int parse_server_spec(const char *spec, struct imap_server *out)
{
    const char *p = spec, *sep, *hstart, *hend;
    char hostbuf[MAX_HOST_LEN + 1];
    size_t hlen;

    memset(out, 0, sizeof(*out));

    sep = strstr(p, "://");
    if (!sep)
        return 0;
    {
        size_t slen = (size_t)(sep - p);
        if (slen == 5 && !strncasecmp(p, "imaps", 5))
            out->mode = MODE_IMAPS;
        else if (slen == 8 && !strncasecmp(p, "starttls", 8))
            out->mode = MODE_STARTTLS;
        else if (slen == 4 && !strncasecmp(p, "imap", 4))
            out->mode = MODE_NONE;
        else
            return 0;
        p = sep + 3;
    }

    if (*p == '[') {                    /* [IPv6] */
        hstart = p + 1;
        hend = strchr(hstart, ']');
        if (!hend)
            return 0;
        p = hend + 1;
    } else {
        hstart = p;
        hend = p + strcspn(p, ":/");
        p = hend;
    }

    hlen = (size_t)(hend - hstart);
    if (hlen == 0 || hlen > MAX_HOST_LEN)
        return 0;
    memcpy(hostbuf, hstart, hlen);
    hostbuf[hlen] = '\0';
    if (!valid_host(hostbuf))
        return 0;

    if (*p == ':') {
        char portbuf[8];
        size_t plen = strcspn(p + 1, "/");
        if (plen == 0 || plen >= sizeof(portbuf))
            return 0;
        memcpy(portbuf, p + 1, plen);
        portbuf[plen] = '\0';
        if (!parse_port(portbuf, &out->port))
            return 0;
        p += 1 + plen;
    }

    if (*p == '/')
        p++;
    if (*p)                             /* paths, queries etc. not allowed */
        return 0;

    if (!out->port)
        out->port = default_port_for(out->mode);
    out->host = strdup(hostbuf);
    return out->host != NULL;
}

static size_t discard_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    (void)ptr;
    (void)ud;
    return size * nmemb;
}

/* Append "@domain" to a name without '@' when domain= is configured. */
static void qualify_name(const struct plugin_ctx *ctx, const char *name,
                         char *out, size_t outsz)
{
    if (ctx->domain && !strchr(name, '@'))
        snprintf(out, outsz, "%s@%s", name, ctx->domain);
    else
        snprintf(out, outsz, "%s", name);
}

/* ------------------------------------------------------------------ */
/* certificate matching                                                */
/* ------------------------------------------------------------------ */

static int is_space(char c)
{
    return c == ' ' || c == '\t';
}

static int load_cert_map(struct plugin_ctx *ctx)
{
    char line[2048];
    int lineno = 0;
    FILE *f = fopen(ctx->cert_map_path, "r");

    if (!f) {
        ctx->log(PLOG_ERR | PLOG_ERRNO, PLUGIN_NAME, "cannot open cert-map %s",
                 ctx->cert_map_path);
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        char *start, *end, *user;
        struct cert_map_entry *grown;

        lineno++;
        if (len == sizeof(line) - 1 && line[len - 1] != '\n' && !feof(f)) {
            ctx->log(PLOG_ERR, PLUGIN_NAME, "%s:%d: line too long",
                     ctx->cert_map_path, lineno);
            goto fail;
        }

        /* trim both ends */
        end = line + len;
        while (end > line && (end[-1] == '\n' || end[-1] == '\r' ||
                              is_space(end[-1])))
            *--end = '\0';
        start = line;
        while (is_space(*start))
            start++;
        if (!*start || *start == '#')
            continue;

        /* the user is the last field; the common name is everything before */
        user = end;
        while (user > start && !is_space(user[-1]))
            user--;
        if (user == start) {
            ctx->log(PLOG_ERR, PLUGIN_NAME,
                     "%s:%d: expected '<common_name> <imap-user>'",
                     ctx->cert_map_path, lineno);
            goto fail;
        }
        end = user;
        while (end > start && is_space(end[-1]))
            end--;
        *end = '\0';

        if (!valid_credential(start, MAX_CN_LEN) ||
            !valid_credential(user, MAX_USER_LEN)) {
            ctx->log(PLOG_ERR, PLUGIN_NAME, "%s:%d: invalid entry",
                     ctx->cert_map_path, lineno);
            goto fail;
        }

        grown = realloc(ctx->cert_map,
                        (ctx->cert_map_len + 1) * sizeof(*grown));
        if (!grown)
            goto fail;
        ctx->cert_map = grown;
        grown[ctx->cert_map_len].cn = strdup(start);
        grown[ctx->cert_map_len].user = strdup(user);
        ctx->cert_map_len++;
        if (!grown[ctx->cert_map_len - 1].cn ||
            !grown[ctx->cert_map_len - 1].user)
            goto fail;
    }

    if (ferror(f)) {
        ctx->log(PLOG_ERR, PLUGIN_NAME, "error reading %s", ctx->cert_map_path);
        goto fail;
    }
    fclose(f);
    if (ctx->cert_map_len == 0)
        ctx->log(PLOG_WARN, PLUGIN_NAME, "cert-map %s has no entries",
                 ctx->cert_map_path);
    return 1;

fail:
    fclose(f);
    return 0;
}

/*
 * Is "login" (already qualified) allowed for the certificate "cn"?
 * Common names in the map are compared exactly; user names are compared
 * case-insensitively after domain= is applied.
 */
static int cert_allows(const struct plugin_ctx *ctx, const char *cn,
                       const char *login)
{
    char name[MAX_LOGIN_LEN];
    int mapped = 0;

    for (size_t i = 0; i < ctx->cert_map_len; i++) {
        if (strcmp(ctx->cert_map[i].cn, cn) != 0)
            continue;
        mapped = 1;
        qualify_name(ctx, ctx->cert_map[i].user, name, sizeof(name));
        if (!strcasecmp(name, login))
            return 1;
    }
    if (mapped)
        return 0;

    qualify_name(ctx, cn, name, sizeof(name));
    return !strcasecmp(name, login);
}

/* ------------------------------------------------------------------ */
/* IMAP authentication                                                 */
/* ------------------------------------------------------------------ */

static enum auth_result imap_try_server(const struct plugin_ctx *ctx,
                                        const struct imap_server *srv,
                                        const char *login_name,
                                        const char *pass)
{
    char url[MAX_HOST_LEN + 32];
    int ipv6 = strchr(srv->host, ':') != NULL;
    CURLcode rc;
    CURL *curl;

    snprintf(url, sizeof(url), "%s://%s%s%s:%d/",
             srv->mode == MODE_IMAPS ? "imaps" : "imap",
             ipv6 ? "[" : "", srv->host, ipv6 ? "]" : "", srv->port);

    curl = curl_easy_init();
    if (!curl)
        return AUTH_ERROR;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERNAME, login_name);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
    /* After LOGIN/AUTHENTICATE succeeds, send a harmless NOOP. */
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "NOOP");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_cb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, ctx->timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, ctx->timeout);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    /* Never send credentials in clear text unless mode is "imap". */
    if (srv->mode == MODE_STARTTLS)
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
    if (ctx->cafile)
        curl_easy_setopt(curl, CURLOPT_CAINFO, ctx->cafile);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, ctx->verify ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, ctx->verify ? 2L : 0L);

    rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (rc == CURLE_OK)
        return AUTH_ACCEPT;
    if (rc == CURLE_LOGIN_DENIED)
        return AUTH_REJECT;

    ctx->log(PLOG_WARN, PLUGIN_NAME, "server %s: %s",
             srv->spec, curl_easy_strerror(rc));
    return AUTH_ERROR;
}

/*
 * Try the configured servers in order according to the policy.
 * Any outcome other than AUTH_ACCEPT means the user is rejected.
 */
static enum auth_result imap_authenticate(const struct plugin_ctx *ctx,
                                          const char *user, const char *pass)
{
    int rejected = 0;

    for (int i = 0; i < ctx->nservers; i++) {
        const struct imap_server *srv = &ctx->servers[i];
        enum auth_result r = imap_try_server(ctx, srv, user, pass);

        if (r == AUTH_ACCEPT) {
            ctx->log(PLOG_NOTE, PLUGIN_NAME, "user '%s' accepted by %s",
                     user, srv->spec);
            return AUTH_ACCEPT;
        }
        if (r == AUTH_REJECT) {
            ctx->log(PLOG_NOTE, PLUGIN_NAME, "user '%s' rejected by %s",
                     user, srv->spec);
            if (ctx->policy == POLICY_FAILOVER)
                return AUTH_REJECT;
            rejected = 1;
        }
        /* AUTH_ERROR: fall through to the next server */
    }

    if (!rejected)
        ctx->log(PLOG_ERR, PLUGIN_NAME,
                 "no IMAP server could verify user '%s'", user);
    return rejected ? AUTH_REJECT : AUTH_ERROR;
}

static void write_auth_control(const char *path, int ok)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ssize_t w;

    if (fd < 0)
        return;
    w = write(fd, ok ? "1" : "0", 1);
    (void)w;
    close(fd);
}

static void free_ctx(struct plugin_ctx *ctx)
{
    if (!ctx)
        return;
    for (int i = 0; i < ctx->nservers; i++) {
        free(ctx->servers[i].spec);
        free(ctx->servers[i].host);
    }
    for (size_t i = 0; i < ctx->cert_map_len; i++) {
        free(ctx->cert_map[i].cn);
        free(ctx->cert_map[i].user);
    }
    free(ctx->cert_map);
    free(ctx->cert_map_path);
    free(ctx->cafile);
    free(ctx->domain);
    free(ctx);
}

/* ------------------------------------------------------------------ */
/* argument parsing                                                    */
/* ------------------------------------------------------------------ */

static int add_server(struct plugin_ctx *ctx, const struct imap_server *s)
{
    if (ctx->nservers >= MAX_SERVERS) {
        ctx->log(PLOG_ERR, PLUGIN_NAME, "too many servers (max %d)",
                 MAX_SERVERS);
        return 0;
    }
    ctx->servers[ctx->nservers++] = *s;
    return 1;
}

static int parse_args(struct plugin_ctx *ctx, const char **argv)
{
    for (int i = 1; argv[i]; i++) {
        const char *a = argv[i];
        const char *v = strchr(a, '=');

        if (!v) {
            ctx->log(PLOG_ERR, PLUGIN_NAME, "bad argument '%s'", a);
            return 0;
        }
        v++;

        if (!strncmp(a, "server=", 7)) {
            struct imap_server s;
            if (!parse_server_spec(v, &s)) {
                ctx->log(PLOG_ERR, PLUGIN_NAME,
                         "invalid server '%s' (expected imaps://host[:port], "
                         "starttls://host[:port] or imap://host[:port])", v);
                free(s.host);
                return 0;
            }
            if (!add_server(ctx, &s))
                return 0;
        } else if (!strncmp(a, "policy=", 7)) {
            if (!strcasecmp(v, "failover"))
                ctx->policy = POLICY_FAILOVER;
            else if (!strcasecmp(v, "any"))
                ctx->policy = POLICY_ANY;
            else {
                ctx->log(PLOG_ERR, PLUGIN_NAME, "unknown policy '%s'", v);
                return 0;
            }
        } else if (!strncmp(a, "cafile=", 7)) {
            free(ctx->cafile);
            ctx->cafile = strdup(v);
        } else if (!strncmp(a, "domain=", 7)) {
            if (!valid_host(v) || strchr(v, ':')) {
                ctx->log(PLOG_ERR, PLUGIN_NAME, "invalid domain '%s'", v);
                return 0;
            }
            free(ctx->domain);
            ctx->domain = strdup(v);
        } else if (!strncmp(a, "timeout=", 8)) {
            ctx->timeout = atol(v);
            if (ctx->timeout <= 0) {
                ctx->log(PLOG_ERR, PLUGIN_NAME, "invalid timeout '%s'", v);
                return 0;
            }
        } else if (!strncmp(a, "match-cert=", 11)) {
            if (strcmp(v, "0") && strcmp(v, "1")) {
                ctx->log(PLOG_ERR, PLUGIN_NAME,
                         "match-cert must be 0 or 1, not '%s'", v);
                return 0;
            }
            ctx->match_cert = v[0] == '1';
        } else if (!strncmp(a, "cert-map=", 9)) {
            if (!*v) {
                ctx->log(PLOG_ERR, PLUGIN_NAME, "cert-map needs a file name");
                return 0;
            }
            free(ctx->cert_map_path);
            ctx->cert_map_path = strdup(v);
        } else if (!strncmp(a, "verify=", 7)) {
            ctx->verify = atoi(v) != 0;
        } else {
            ctx->log(PLOG_ERR, PLUGIN_NAME, "unknown argument '%s'", a);
            return 0;
        }
    }
    return 1;
}

/* Check the server list and build the names used in log messages. */
static int finalize_servers(struct plugin_ctx *ctx)
{
    if (ctx->nservers == 0) {
        ctx->log(PLOG_ERR, PLUGIN_NAME,
                 "no IMAP server configured (use server=imaps://host)");
        return 0;
    }

    for (int i = 0; i < ctx->nservers; i++) {
        struct imap_server *s = &ctx->servers[i];
        char buf[MAX_HOST_LEN + 32];
        int ipv6 = strchr(s->host, ':') != NULL;

        snprintf(buf, sizeof(buf), "%s://%s%s%s:%d", mode_name(s->mode),
                 ipv6 ? "[" : "", s->host, ipv6 ? "]" : "", s->port);
        s->spec = strdup(buf);
        if (!s->spec)
            return 0;

        if (s->mode == MODE_NONE)
            ctx->log(PLOG_WARN, PLUGIN_NAME,
                     "%s sends passwords in clear text", s->spec);
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* OpenVPN plugin entry points                                         */
/* ------------------------------------------------------------------ */

OPENVPN_EXPORT int openvpn_plugin_min_version_required_v1(void)
{
    return 3;
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3(const int v3structver,
                       struct openvpn_plugin_args_open_in const *args,
                       struct openvpn_plugin_args_open_return *ret)
{
    struct plugin_ctx *ctx;

    if (v3structver < OPENVPN_PLUGINv3_STRUCTVER)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    ctx->policy = POLICY_FAILOVER;
    ctx->timeout = 10;
    ctx->verify = 1;
    ctx->log = args->callbacks->plugin_log;

    if (!parse_args(ctx, args->argv) || !finalize_servers(ctx))
        goto fail;

    if (ctx->cert_map_path && !ctx->match_cert) {
        ctx->log(PLOG_ERR, PLUGIN_NAME, "cert-map= requires match-cert=1");
        goto fail;
    }
    if (ctx->cert_map_path && !load_cert_map(ctx))
        goto fail;

    if (!ctx->verify)
        ctx->log(PLOG_WARN, PLUGIN_NAME,
                 "verify=0: IMAP server certificates are NOT checked");

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        ctx->log(PLOG_ERR, PLUGIN_NAME, "curl_global_init failed");
        goto fail;
    }

    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    ret->handle = (openvpn_plugin_handle_t)ctx;

    for (int i = 0; i < ctx->nservers; i++)
        ctx->log(PLOG_NOTE, PLUGIN_NAME, "server %d: %s", i + 1,
                 ctx->servers[i].spec);
    ctx->log(PLOG_NOTE, PLUGIN_NAME, "policy=%s timeout=%lds",
             ctx->policy == POLICY_ANY ? "any" : "failover", ctx->timeout);
    if (ctx->match_cert)
        ctx->log(PLOG_NOTE, PLUGIN_NAME,
                 "match-cert enabled, %zu cert-map entries", ctx->cert_map_len);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;

fail:
    free_ctx(ctx);
    return OPENVPN_PLUGIN_FUNC_ERROR;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int v3structver,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *ret)
{
    struct plugin_ctx *ctx = (struct plugin_ctx *)args->handle;
    const char *user, *pass, *acf, *ip;
    char login[MAX_LOGIN_LEN];
    pid_t pid;
    int status;

    (void)ret;
    if (v3structver < OPENVPN_PLUGINv3_STRUCTVER)
        return OPENVPN_PLUGIN_FUNC_ERROR;
    if (args->type != OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    user = get_env("username", args->envp);
    pass = get_env("password", args->envp);
    acf  = get_env("auth_control_file", args->envp);
    ip   = get_env("untrusted_ip", args->envp);
    if (!ip)
        ip = get_env("untrusted_ip6", args->envp);
    if (!ip)
        ip = "?";

    if (!valid_credential(user, MAX_USER_LEN) ||
        !valid_credential(pass, MAX_PASS_LEN)) {
        ctx->log(PLOG_WARN, PLUGIN_NAME,
                 "rejecting malformed credentials from %s", ip);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    qualify_name(ctx, user, login, sizeof(login));

    /* Certificate binding: checked before any IMAP server is contacted. */
    if (ctx->match_cert) {
        const char *cn = get_env("common_name", args->envp);

        if (!valid_credential(cn, MAX_CN_LEN)) {
            ctx->log(PLOG_WARN, PLUGIN_NAME,
                     "user '%s' from %s: no valid client certificate name, "
                     "required by match-cert", login, ip);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        if (!cert_allows(ctx, cn, login)) {
            ctx->log(PLOG_WARN, PLUGIN_NAME,
                     "user '%s' from %s does not match certificate '%s'",
                     login, ip, cn);
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }

    /* No deferred auth available: authenticate synchronously. */
    if (!acf) {
        return imap_authenticate(ctx, login, pass) == AUTH_ACCEPT
               ? OPENVPN_PLUGIN_FUNC_SUCCESS : OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* Deferred auth: double fork so no zombies are left behind. */
    pid = fork();
    if (pid < 0) {
        ctx->log(PLOG_ERR | PLOG_ERRNO, PLUGIN_NAME, "fork failed");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (pid > 0) {
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR)
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
            return OPENVPN_PLUGIN_FUNC_DEFERRED;
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    /* first child */
    pid = fork();
    if (pid < 0)
        _exit(1);
    if (pid > 0)
        _exit(0);

    /* grandchild: do the actual IMAP check */
    write_auth_control(acf, imap_authenticate(ctx, login, pass) == AUTH_ACCEPT);
    _exit(0);
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    free_ctx((struct plugin_ctx *)handle);
    curl_global_cleanup();
}
