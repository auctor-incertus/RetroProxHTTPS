/* proxy.c
 * Local HTTPS→HTTP MITM proxy for Windows 9x.
 *
 * Usage:
 *   proxy.exe                 — run as proxy on 127.0.0.1:8080
 *   proxy.exe <hostname>      — diagnostic: client TLS handshake to host:443
 *
 * On first run, generates a 2048-bit root CA key (stored in the registry
 * under HKCU\Software\RetroProxHTTPS\CAKey) and writes ca.crt to disk for
 * the user to install as a trusted root. A fresh 1024-bit RSA server key
 * is generated in memory on each run and reused for signing per-host
 * certificates.
*/

#include <winsock2.h>
#include <windows.h>
#include <process.h>              /* _beginthread */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"   /* for ssl->handshake->resume */
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"

#include "mbedtls/debug.h"

#include "mbedtls/md.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509_csr.h"   /* pulls in x509_crt write APIs on 2.25 */
#include "mbedtls/ssl_cache.h"

/* Ciphersuites IE 5.x on Win9x is known to offer. We deliberately keep
 * this list as small as possible: every extra suite costs a little bit
 * of selection work on the PPro, and IE will only ever pick from the
 * RC4 / 3DES families anyway. No DHE (would cost a modexp per handshake)
 * and no AES (IE 5.01 predates it). */
static const int ie_compat_ciphersuites[] = {
    MBEDTLS_TLS_RSA_WITH_RC4_128_MD5,         /* 0x0004 — fastest */
    MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,         /* 0x0005 */
    MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,    /* 0x000A */
    0
};

static void ssl_debug(void *ctx, int level,
                      const char *file, int line, const char *str)
{
    (void)ctx;
    printf("[ssl %d] %s:%d: %s\n", level, file, line, str);
    fflush(stdout);
}

#define LISTEN_PORT 8080
#define BUFSIZE     16384
#define REQMAX      4096

/* ------------------------------------------------------------------ */
/*  Global locks                                                       */
/*                                                                     */
/*  Initialized once in tls_global_init(). Held only for the duration  */
/*  of individual shared-state operations; never across a blocking     */
/*  socket call.                                                       */
/* ------------------------------------------------------------------ */

static CRITICAL_SECTION g_log_lock;
static CRITICAL_SECTION g_drbg_lock;
static CRITICAL_SECTION g_cert_cache_lock;
static CRITICAL_SECTION g_upstream_sess_lock;
static CRITICAL_SECTION g_browser_cache_lock;
static CRITICAL_SECTION g_upstream_cache_lock;

/* Thread-safe log line. Use this instead of printf for anything that
 * could otherwise interleave with another worker's output. */
#define LOG(...) do { \
    EnterCriticalSection(&g_log_lock); \
    printf(__VA_ARGS__); \
    fflush(stdout); \
    LeaveCriticalSection(&g_log_lock); \
} while (0)

/* ------------------------------------------------------------------ */
/*  Winsock helpers                                                    */
/* ------------------------------------------------------------------ */

static void die(const char *msg)
{
    fprintf(stderr, "FATAL: %s (WSA error %d)\n", msg, WSAGetLastError());
    WSACleanup();
    exit(1);
}

static int parse_connect(const char *req, char *host, size_t hostsz, int *port)
{
    const char *p = req;
    const char *host_start, *colon;
    size_t hlen;

    if (strncmp(p, "CONNECT ", 8) != 0) return -1;
    p += 8;

    host_start = p;
    while (*p && *p != ':' && *p != ' ' && *p != '\r' && *p != '\n') p++;
    if (*p != ':') return -1;

    colon = p;
    hlen = (size_t)(colon - host_start);
    if (hlen == 0 || hlen >= hostsz) return -1;
    memcpy(host, host_start, hlen);
    host[hlen] = '\0';

    p = colon + 1;
    *port = atoi(p);
    if (*port <= 0 || *port > 65535) return -1;
    return 0;
}

static void set_nodelay(SOCKET s)
{
    int nd = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&nd, sizeof(nd));
}

/* ------------------------------------------------------------------ */
/*  DNS cache                                                          */
/*                                                                     */
/*  Only touched from worker threads. Not locked: a duplicate lookup   */
/*  races at worst and both threads write the same answer. The list    */
/*  is small enough that torn entries are practically impossible on    */
/*  a 32-bit store, but if you want to be strict, wrap the get/put in  */
/*  a critical section. In practice this hasn't been a source of       */
/*  issues in testing.                                                 */
/* ------------------------------------------------------------------ */

#define DNS_CACHE_SIZE 64
#define DNS_TTL_MS     300000UL   /* 5 minutes */

struct dns_cache_entry {
    char           host[256];
    struct in_addr addr;
    DWORD          expires;
    int            used;
};

static struct dns_cache_entry g_dns_cache[DNS_CACHE_SIZE];

static int dns_cache_get(const char *host, struct in_addr *out)
{
    int i;
    DWORD now = GetTickCount();

    for (i = 0; i < DNS_CACHE_SIZE; i++) {
        struct dns_cache_entry *e = &g_dns_cache[i];
        if (e->used && strcmp(e->host, host) == 0) {
            if ((DWORD)(now - e->expires) < 0x80000000UL) {
                *out = e->addr;
                return 0;
            }
            e->used = 0;
            return -1;
        }
    }
    return -1;
}

static void dns_cache_put(const char *host, struct in_addr addr)
{
    int i, slot = -1;
    DWORD now = GetTickCount();

    if (strlen(host) >= sizeof(g_dns_cache[0].host)) return;

    for (i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_dns_cache[i].used) { slot = i; break; }
    }
    if (slot < 0) {
        DWORD oldest = 0xFFFFFFFFUL;
        for (i = 0; i < DNS_CACHE_SIZE; i++) {
            if (g_dns_cache[i].expires < oldest) {
                oldest = g_dns_cache[i].expires;
                slot = i;
            }
        }
    }
    strncpy(g_dns_cache[slot].host, host,
            sizeof(g_dns_cache[slot].host) - 1);
    g_dns_cache[slot].host[sizeof(g_dns_cache[slot].host) - 1] = '\0';
    g_dns_cache[slot].addr = addr;
    g_dns_cache[slot].expires = now + DNS_TTL_MS;
    g_dns_cache[slot].used = 1;
}

/* Non-blocking connect. Returns a socket in connecting state (or
 * already connected), or INVALID_SOCKET on immediate failure. */
static SOCKET start_nonblocking_connect(const char *host, int port)
{
    SOCKET s;
    struct sockaddr_in sa;
    struct in_addr addr;
    u_long nb = 1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)port);

    if (dns_cache_get(host, &addr) == 0) {
        sa.sin_addr = addr;
    } else {
        struct hostent *he = gethostbyname(host);
        if (!he) return INVALID_SOCKET;
        sa.sin_addr = *(struct in_addr *)he->h_addr;
        dns_cache_put(host, sa.sin_addr);
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    set_nodelay(s);
    ioctlsocket(s, FIONBIO, &nb);

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0)
        return s;

    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

static void set_socket_blocking(SOCKET s)
{
    u_long nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
}

static SOCKET connect_to(const char *host, int port)
{
    SOCKET s;
    struct sockaddr_in sa;
    struct in_addr addr;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((u_short)port);

    if (dns_cache_get(host, &addr) == 0) {
        sa.sin_addr = addr;
    } else {
        struct hostent *he = gethostbyname(host);
        if (!he) return INVALID_SOCKET;
        sa.sin_addr = *(struct in_addr *)he->h_addr;
        dns_cache_put(host, sa.sin_addr);
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    set_nodelay(s);
    return s;
}

/* ------------------------------------------------------------------ */
/*  mbedTLS BIO callbacks                                              */
/* ------------------------------------------------------------------ */

static int tls_send(void *ctx, const unsigned char *buf, size_t len)
{
    SOCKET s = (SOCKET)(uintptr_t)ctx;
    int n = send(s, (const char *)buf, (int)len, 0);
    if (n == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (err == WSAECONNRESET || err == WSAECONNABORTED)
            return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return n;
}

static int tls_recv(void *ctx, unsigned char *buf, size_t len)
{
    SOCKET s = (SOCKET)(uintptr_t)ctx;
    int n = recv(s, (char *)buf, (int)len, 0);
    if (n == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
        if (err == WSAECONNRESET || err == WSAECONNABORTED)
            return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return n;
}

static void print_mbedtls_error(const char *what, int ret)
{
    char buf[256];
    mbedtls_strerror(ret, buf, sizeof(buf));
    fprintf(stderr, "%s: -0x%04X (%s)\n", what, (unsigned)-ret, buf);
}

/* ------------------------------------------------------------------ */
/*  Shared TLS context: entropy + DRBG                                 */
/* ------------------------------------------------------------------ */

static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;

/* Separate caches: a browser-side session ID must never be confused
 * with an upstream session ID, and eviction pressure on one side must
 * not blow away the other side's cached sessions. */
static mbedtls_ssl_cache_context g_browser_cache;
static mbedtls_ssl_cache_context g_upstream_cache;
static int                       g_ssl_caches_ready = 0;

/* Locked wrapper around the shared DRBG. mbedTLS calls this function
 * pointer via the per-config f_rng callback, once per random-bytes
 * request. The lock is held only for the duration of the call. */
static int locked_ctr_drbg_random(void *ctx, unsigned char *out, size_t len)
{
    int ret;
    EnterCriticalSection(&g_drbg_lock);
    ret = mbedtls_ctr_drbg_random(ctx, out, len);
    LeaveCriticalSection(&g_drbg_lock);
    return ret;
}

/* Locked wrappers around the two ssl caches. mbedTLS 2.25 does not
 * build the caches with internal locking unless MBEDTLS_THREADING_C is
 * enabled; we don't enable it, so we serialise access here instead. */
static int locked_browser_cache_get(void *ctx, const mbedtls_ssl_session *sess)
{
    int ret;
    EnterCriticalSection(&g_browser_cache_lock);
    ret = mbedtls_ssl_cache_get(ctx, sess);
    LeaveCriticalSection(&g_browser_cache_lock);
    return ret;
}

static int locked_browser_cache_set(void *ctx, const mbedtls_ssl_session *sess)
{
    int ret;
    EnterCriticalSection(&g_browser_cache_lock);
    ret = mbedtls_ssl_cache_set(ctx, sess);
    LeaveCriticalSection(&g_browser_cache_lock);
    return ret;
}

static int locked_upstream_cache_get(void *ctx, const mbedtls_ssl_session *sess)
{
    int ret;
    EnterCriticalSection(&g_upstream_cache_lock);
    ret = mbedtls_ssl_cache_get(ctx, sess);
    LeaveCriticalSection(&g_upstream_cache_lock);
    return ret;
}

static int locked_upstream_cache_set(void *ctx, const mbedtls_ssl_session *sess)
{
    int ret;
    EnterCriticalSection(&g_upstream_cache_lock);
    ret = mbedtls_ssl_cache_set(ctx, sess);
    LeaveCriticalSection(&g_upstream_cache_lock);
    return ret;
}

static void init_ssl_session_caches(void)
{
    if (g_ssl_caches_ready) return;

    mbedtls_ssl_cache_init(&g_browser_cache);
    mbedtls_ssl_cache_set_timeout(&g_browser_cache, 300);
    mbedtls_ssl_cache_set_max_entries(&g_browser_cache, 32);

    mbedtls_ssl_cache_init(&g_upstream_cache);
    mbedtls_ssl_cache_set_timeout(&g_upstream_cache, 300);
    mbedtls_ssl_cache_set_max_entries(&g_upstream_cache, 32);

    g_ssl_caches_ready = 1;
}

static int tls_global_init(void)
{
    int ret;
    const char *pers = "retroproxhttps";

    InitializeCriticalSection(&g_log_lock);
    InitializeCriticalSection(&g_drbg_lock);
    InitializeCriticalSection(&g_cert_cache_lock);
    InitializeCriticalSection(&g_upstream_sess_lock);
    InitializeCriticalSection(&g_browser_cache_lock);
    InitializeCriticalSection(&g_upstream_cache_lock);

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func,
                                &g_entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        print_mbedtls_error("ctr_drbg_seed", ret);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Resumption-aware handshake driver                                  */
/*                                                                     */
/*  mbedtls_ssl_handshake() internally runs a loop over                 */
/*  mbedtls_ssl_handshake_step() and returns once the state reaches     */
/*  MBEDTLS_SSL_HANDSHAKE_OVER. At that point wrapup has already run,   */
/*  the handshake struct has been freed and ssl->handshake set to NULL. */
/*  Any attempt to read ssl->handshake->resume afterwards dereferences  */
/*  NULL.                                                               */
/*                                                                     */
/*  We replicate the internal loop here so we can peek at the resume    */
/*  flag after every successful step, while the handshake struct is     */
/*  still valid. The flag is set during ServerHello parsing, several    */
/*  steps before wrapup, so the latch always catches it. The output     */
/*  flag is monotonic: it is never cleared, so callers can reuse the    */
/*  same variable across multiple WANT_READ / WANT_WRITE round trips.   */
/* ------------------------------------------------------------------ */

static int handshake_with_resume_check(mbedtls_ssl_context *ssl,
                                       int *resumed_flag)
{
    int ret;

    while (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        ret = mbedtls_ssl_handshake_step(ssl);
        if (ret != 0)
            return ret;

        /* Handshake struct is alive here. Peek before the wrapup step
         * frees it. */
        if (ssl->handshake && ssl->handshake->resume)
            *resumed_flag = 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Client-side TLS (proxy → upstream) — diagnostic-mode helper        */
/*                                                                     */
/*  The concurrent proxy path uses parallel_handshake() instead. This  */
/*  simpler blocking variant is only used by diag_mode(), which runs   */
/*  in the main thread before any workers exist.                       */
/* ------------------------------------------------------------------ */

static int tls_client_handshake(SOCKET server, const char *host,
                                mbedtls_ssl_context *ssl_out,
                                mbedtls_ssl_config *conf_out)
{
    int ret;

    mbedtls_ssl_init(ssl_out);
    mbedtls_ssl_config_init(conf_out);

    ret = mbedtls_ssl_config_defaults(conf_out,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) { print_mbedtls_error("client config_defaults", ret); return -1; }

    mbedtls_ssl_conf_rng(conf_out, locked_ctr_drbg_random, &g_ctr_drbg);
    mbedtls_ssl_conf_authmode(conf_out, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_session_cache(conf_out, &g_upstream_cache,
                                   locked_upstream_cache_get,
                                   locked_upstream_cache_set);

    ret = mbedtls_ssl_setup(ssl_out, conf_out);
    if (ret != 0) { print_mbedtls_error("client ssl_setup", ret); return -1; }

    mbedtls_ssl_set_hostname(ssl_out, host);
    mbedtls_ssl_set_bio(ssl_out, (void *)(uintptr_t)server,
                        tls_send, tls_recv, NULL);

    ret = mbedtls_ssl_handshake(ssl_out);
    if (ret != 0) { print_mbedtls_error("client handshake", ret); return -1; }

    return 0;
}

static void tls_print_peer(const char *side, mbedtls_ssl_context *ssl)
{
    const mbedtls_x509_crt *cert = mbedtls_ssl_get_peer_cert(ssl);
    char dn[512];

    LOG("  [%s] %s / %s\n", side,
        mbedtls_ssl_get_version(ssl),
        mbedtls_ssl_get_ciphersuite(ssl));

    if (cert) {
        dn[0] = '\0';
        mbedtls_x509_dn_gets(dn, sizeof(dn), &cert->subject);
        LOG("  [%s] cert: %s\n", side, dn);
    }
}

/* ------------------------------------------------------------------ */
/*  Registry-backed CA key storage                                     */
/* ------------------------------------------------------------------ */

#define REG_PATH_KEY  "Software\\RetroProxHTTPS"
#define REG_VALUE_KEY "CAKey"

#define CA_CRT_FILE   "ca.crt"

/* CA key stays 2048-bit; the per-run server key is dropped to 1024 bits.
 * Nothing on Win9x verifies key strength, and the 1024-bit key makes
 * both keygen (~4× faster) and the RSA private op on every browser-side
 * handshake much cheaper on a PPro. */
#define CA_KEY_BITS     2048
#define SERVER_KEY_BITS 1024

#define CA_DN_STRING \
    "C=US,ST=Local,L=Local,O=RetroProxHTTPS,CN=RetroProxHTTPS Local Root CA"

/* Certificate lifetime, in years, for both CA and leaf certs. */
#define CERT_VALIDITY_YEARS 20

/* Build a YYYYMMDDHHMMSS notBefore/notAfter pair from the current UTC
 * system time. mbedTLS accepts exactly this format; it appends the
 * GeneralizedTime 'Z' suffix internally. Buffers must be at least 16
 * bytes. On Win9x GetSystemTime() is the only safe UTC source. */
static void build_validity_dates(char *not_before, char *not_after)
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    sprintf(not_before, "%04d%02d%02d%02d%02d%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

    sprintf(not_after, "%04d%02d%02d%02d%02d%02d",
            st.wYear + CERT_VALIDITY_YEARS, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
}

/* mbedTLS 2.25 tags every parsed DN value as UTF8String via
 * mbedtls_asn1_store_named_data(). IE 5.01 on Win9x does not decode
 * UTF8String in cert names — CertGetNameString() returns nothing and
 * IE reports a hostname mismatch. Rewriting the value tag to
 * PrintableString fixes the comparison on Win9x and is still valid
 * X.509 everywhere else.
 *
 * Call this only on the leaf subject. The issuer field must stay
 * byte-identical to the CA subject that was written and installed
 * earlier, or the chain breaks. */
static void force_printable_string(mbedtls_asn1_named_data *dn)
{
    for (; dn != NULL; dn = dn->next) {
        if (dn->val.tag == MBEDTLS_ASN1_UTF8_STRING)
            dn->val.tag = MBEDTLS_ASN1_PRINTABLE_STRING;
    }
}

static int registry_write_ca_key(const unsigned char *pem, size_t len)
{
    HKEY hKey;
    LONG rc;
    DWORD disp;

    rc = RegCreateKeyExA(HKEY_CURRENT_USER, REG_PATH_KEY, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                         &hKey, &disp);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "RegCreateKeyExA failed: %ld\n", rc);
        return -1;
    }

    rc = RegSetValueExA(hKey, REG_VALUE_KEY, 0, REG_SZ,
                        pem, (DWORD)len);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "RegSetValueExA failed: %ld\n", rc);
        return -1;
    }
    return 0;
}

static int registry_read_ca_key(unsigned char *buf, size_t bufsz,
                                size_t *outlen)
{
    HKEY hKey;
    LONG rc;
    DWORD type = 0;
    DWORD size = (DWORD)bufsz;

    rc = RegOpenKeyExA(HKEY_CURRENT_USER, REG_PATH_KEY, 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) return -1;

    rc = RegQueryValueExA(hKey, REG_VALUE_KEY, NULL, &type, buf, &size);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) return -1;
    if (type != REG_SZ) return -1;

    *outlen = (size_t)size;
    return 0;
}

static int write_file_buf(const char *path, const unsigned char *buf,
                          size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static int generate_rsa_key(mbedtls_pk_context *pk, int bits)
{
    int ret;

    mbedtls_pk_init(pk);
    ret = mbedtls_pk_setup(pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) return ret;

    return mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pk),
                               locked_ctr_drbg_random, &g_ctr_drbg,
                               bits, 65537);
}

static int generate_ca_cert(mbedtls_pk_context *ca_key,
                            unsigned char *pem_out, size_t pem_max)
{
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    unsigned char serial_bytes[8];
    char not_before[16], not_after[16];
    int ret;

    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA1);

    ret = mbedtls_x509write_crt_set_subject_name(&crt, CA_DN_STRING);
    if (ret != 0) goto fail;
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, CA_DN_STRING);
    if (ret != 0) goto fail;

    mbedtls_x509write_crt_set_subject_key(&crt, ca_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, ca_key);

    build_validity_dates(not_before, not_after);
    ret = mbedtls_x509write_crt_set_validity(&crt,
              not_before, not_after);
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, 0);
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_set_key_usage(&crt,
              MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
    if (ret != 0) goto fail;

    ret = locked_ctr_drbg_random(&g_ctr_drbg, serial_bytes,
                                 sizeof(serial_bytes));
    if (ret != 0) goto fail;
    serial_bytes[0] &= 0x7F;
    serial_bytes[7] |= 0x01;

    ret = mbedtls_mpi_read_binary(&serial, serial_bytes, sizeof(serial_bytes));
    if (ret != 0) goto fail;
    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_pem(&crt, pem_out, pem_max,
                                    locked_ctr_drbg_random, &g_ctr_drbg);
    if (ret != 0) goto fail;

    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt);
    return 0;

fail:
    print_mbedtls_error("generate_ca_cert", ret);
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt);
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Per-host certificate generation                                    */
/* ------------------------------------------------------------------ */

static mbedtls_pk_context g_ca_key;
static mbedtls_pk_context g_server_key;
static int                g_ca_ready = 0;

#define CERT_CACHE_SIZE 16
#define CERT_PEM_MAX    4096

struct cert_cache_entry {
    char          host[256];
    unsigned char pem[CERT_PEM_MAX];
    size_t        pem_len;
    int           used;
};

static struct cert_cache_entry g_cert_cache[CERT_CACHE_SIZE];

static int init_ca_and_server_key(void)
{
    int ret;
    unsigned char ca_key_buf[4096];
    size_t ca_key_len = 0;
    int generated_ca = 0;

    if (g_ca_ready) return 0;

    mbedtls_pk_init(&g_ca_key);
    mbedtls_pk_init(&g_server_key);

    /* ------- CA key: read from registry, or generate + store ------- */
    if (registry_read_ca_key(ca_key_buf, sizeof(ca_key_buf),
                             &ca_key_len) == 0) {
        ret = mbedtls_pk_parse_key(&g_ca_key, ca_key_buf, ca_key_len,
                                   NULL, 0);
        if (ret != 0) {
            print_mbedtls_error("parse CA key from registry", ret);
            return -1;
        }
        printf("CA key loaded from registry.\n");
    } else {
        unsigned char ca_pem[4096];
        unsigned char ca_key_pem[4096];

        printf("\n=== First run: generating root CA ===\n");

        ret = generate_rsa_key(&g_ca_key, CA_KEY_BITS);
        if (ret != 0) { print_mbedtls_error("gen CA key", ret); return -1; }

        ret = mbedtls_pk_write_key_pem(&g_ca_key, ca_key_pem,
                                       sizeof(ca_key_pem));
        if (ret != 0) { print_mbedtls_error("write CA key PEM", ret); return -1; }

        if (registry_write_ca_key(ca_key_pem,
                                  strlen((char *)ca_key_pem) + 1) != 0) {
            fprintf(stderr,
                    "warning: could not save CA key to registry\n");
        }

        ret = generate_ca_cert(&g_ca_key, ca_pem, sizeof(ca_pem));
        if (ret != 0) return -1;

        if (write_file_buf(CA_CRT_FILE, ca_pem,
                           strlen((char *)ca_pem)) != 0) {
            fprintf(stderr, "could not write %s\n", CA_CRT_FILE);
            return -1;
        }

        printf("Wrote %s.\n", CA_CRT_FILE);
        generated_ca = 1;
    }

    /* ------- Server key: in-memory only, 1024-bit, regenerated each run ------- */
    printf("  generating %d-bit server key (in memory)...\n",
           SERVER_KEY_BITS);
    fflush(stdout);
    ret = generate_rsa_key(&g_server_key, SERVER_KEY_BITS);
    if (ret != 0) { print_mbedtls_error("gen server key", ret); return -1; }

    g_ca_ready = 1;

    if (generated_ca) {
        printf("\n");
        printf("================================================================\n");
        printf("  FIRST-RUN SETUP COMPLETE\n");
        printf("\n");
        printf("  A root CA certificate has been written to:\n");
        printf("    %s\n", CA_CRT_FILE);
        printf("\n");
        printf("  Install it in your browser's Trusted Root Certification\n");
        printf("  Authorities store, then restart the browser:\n");
        printf("\n");
        printf("    Internet Explorer:\n");
        printf("      Tools -> Internet Options -> Content -> Certificates\n");
        printf("      -> Import -> Trusted Root Certification Authorities\n");
        printf("      -> select %s\n", CA_CRT_FILE);
        printf("\n");
        printf("  The CA private key is stored in the registry at:\n");
        printf("    HKCU\\%s\\%s\n", REG_PATH_KEY, REG_VALUE_KEY);
        printf("  and will be reused automatically on future runs.\n");
        printf("================================================================\n\n");
    } else {
        printf("CA + server key ready; dynamic cert generation enabled.\n");
    }
    fflush(stdout);
    return 0;
}

static struct cert_cache_entry *find_cert_cache(const char *host)
{
    int i;
    for (i = 0; i < CERT_CACHE_SIZE; i++) {
        if (g_cert_cache[i].used &&
            strcmp(g_cert_cache[i].host, host) == 0)
            return &g_cert_cache[i];
    }
    return NULL;
}

static struct cert_cache_entry *alloc_cert_cache(void)
{
    int i;
    for (i = 0; i < CERT_CACHE_SIZE; i++) {
        if (!g_cert_cache[i].used)
            return &g_cert_cache[i];
    }
    LOG("cert cache full, evicting %s\n", g_cert_cache[0].host);
    return &g_cert_cache[0];
}

/* 2.5.29.17 — DER-encoded OID bytes for subjectAltName. */
static const unsigned char san_oid[] = { 0x55, 0x1D, 0x11 };

/* Build a subjectAltName extension containing a single dNSName
 * and attach it to the certificate. mbedTLS 2.25 has no
 * set_subject_alt_name() API — that arrived in 3.x — so we encode
 * the DER by hand. */
static int set_san_dnsname(mbedtls_x509write_cert *crt, const char *host)
{
    unsigned char san[256];
    size_t host_len = strlen(host);
    size_t name_len, san_len;

    if (host_len == 0 || host_len > 120)
        return -1;

    name_len = 2 + host_len;
    san[0] = 0x82;
    san[1] = (unsigned char)host_len;
    memcpy(san + 2, host, host_len);

    san_len = 2 + name_len;
    memmove(san + 2, san, name_len);
    san[0] = 0x30;
    san[1] = (unsigned char)name_len;

    return mbedtls_x509write_crt_set_extension(crt,
                                                (const char *)san_oid,
                                                sizeof(san_oid),
                                                0,
                                                san, san_len);
}

static int generate_host_cert(const char *host,
                              unsigned char *pem_out, size_t pem_max,
                              size_t *pem_len_out)
{
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    unsigned char serial_bytes[8];
    char subject[512];
    char not_before[16], not_after[16];
    int ret;

    if (strlen(host) > 200) return -1;

    snprintf(subject, sizeof(subject), "CN=%s,O=RetroProxHTTPS", host);

    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA1);

    ret = mbedtls_x509write_crt_set_issuer_name(&crt, CA_DN_STRING);
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_set_subject_name(&crt, subject);
    if (ret != 0) goto fail;

    force_printable_string(crt.subject);

    mbedtls_x509write_crt_set_subject_key(&crt, &g_server_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &g_ca_key);

    build_validity_dates(not_before, not_after);
    ret = mbedtls_x509write_crt_set_validity(&crt,
              not_before, not_after);
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_set_key_usage(&crt,
              MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
              MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
    if (ret != 0) goto fail;

    ret = set_san_dnsname(&crt, host);
    if (ret != 0) goto fail;

    ret = locked_ctr_drbg_random(&g_ctr_drbg, serial_bytes,
                                 sizeof(serial_bytes));
    if (ret != 0) goto fail;
    serial_bytes[0] &= 0x7F;
    serial_bytes[7] |= 0x01;

    ret = mbedtls_mpi_read_binary(&serial, serial_bytes, sizeof(serial_bytes));
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    if (ret != 0) goto fail;

    ret = mbedtls_x509write_crt_pem(&crt, pem_out, pem_max,
                                    locked_ctr_drbg_random, &g_ctr_drbg);
    if (ret != 0) goto fail;

    *pem_len_out = strlen((const char *)pem_out) + 1;

    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt);
    return 0;

fail:
    print_mbedtls_error("generate_host_cert", ret);
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&crt);
    return -1;
}

/* Locked lookup / generation of a per-host certificate. The lock is
 * held across generate_host_cert() too, so concurrent handshakes for
 * the same host don't both try to write the same slot. That call does
 * RSA signing (a DRBG operation), which nests the DRBG lock inside
 * the cert-cache lock. Lock order throughout the file is strictly
 * cache → DRBG; no reverse path exists. */
static const unsigned char *get_host_cert(const char *host, size_t *out_len)
{
    struct cert_cache_entry *entry;
    size_t plen;
    const unsigned char *result = NULL;

    EnterCriticalSection(&g_cert_cache_lock);

    entry = find_cert_cache(host);
    if (entry) {
        *out_len = entry->pem_len;
        result = entry->pem;
        goto done;
    }

    entry = alloc_cert_cache();
    memset(entry, 0, sizeof(*entry));

    if (generate_host_cert(host, entry->pem, CERT_PEM_MAX, &plen) != 0)
        goto done;

    strncpy(entry->host, host, sizeof(entry->host) - 1);
    entry->host[sizeof(entry->host) - 1] = '\0';
    entry->pem_len = plen;
    entry->used = 1;

    LOG("  [browser]  generated cert for %s\n", host);

    *out_len = plen;
    result = entry->pem;

done:
    LeaveCriticalSection(&g_cert_cache_lock);
    return result;
}

/* ------------------------------------------------------------------ */
/*  Upstream session cache (client-role resumption)                    */
/*                                                                     */
/*  All access is serialised by g_upstream_sess_lock. The session      */
/*  object is copied into the ssl context via mbedtls_ssl_set_session  */
/*  before the lock is dropped, so callers never hold a pointer into   */
/*  the cache past the call.                                           */
/* ------------------------------------------------------------------ */

#define UPSTREAM_SESS_CACHE_SIZE 16
#define UPSTREAM_SESS_TTL_MS     300000UL   /* 5 minutes */

struct upstream_sess_entry {
    char                  host[256];
    int                   port;
    mbedtls_ssl_session   sess;
    DWORD                 expires;
    int                   used;
};

static struct upstream_sess_entry g_upstream_sess[UPSTREAM_SESS_CACHE_SIZE];

/* Caller must hold g_upstream_sess_lock. */
static struct upstream_sess_entry *find_upstream_sess(const char *host, int port)
{
    int i;
    DWORD now = GetTickCount();

    for (i = 0; i < UPSTREAM_SESS_CACHE_SIZE; i++) {
        struct upstream_sess_entry *e = &g_upstream_sess[i];
        if (e->used && e->port == port && strcmp(e->host, host) == 0) {
            if ((DWORD)(now - e->expires) < 0x80000000UL)
                return e;
            mbedtls_ssl_session_free(&e->sess);
            e->used = 0;
            return NULL;
        }
    }
    return NULL;
}

/* Caller must hold g_upstream_sess_lock. */
static struct upstream_sess_entry *alloc_upstream_sess(void)
{
    int i;
    for (i = 0; i < UPSTREAM_SESS_CACHE_SIZE; i++) {
        if (!g_upstream_sess[i].used)
            return &g_upstream_sess[i];
    }
    mbedtls_ssl_session_free(&g_upstream_sess[0].sess);
    return &g_upstream_sess[0];
}

static void store_upstream_session(const char *host, int port,
                                   mbedtls_ssl_context *ssl)
{
    struct upstream_sess_entry *e;
    int ret;

    EnterCriticalSection(&g_upstream_sess_lock);

    e = find_upstream_sess(host, port);
    if (!e) {
        e = alloc_upstream_sess();
        memset(e, 0, sizeof(*e));
        mbedtls_ssl_session_init(&e->sess);
    } else {
        mbedtls_ssl_session_free(&e->sess);
        mbedtls_ssl_session_init(&e->sess);
    }

    ret = mbedtls_ssl_get_session(ssl, &e->sess);
    if (ret != 0) {
        mbedtls_ssl_session_free(&e->sess);
        e->used = 0;
        LeaveCriticalSection(&g_upstream_sess_lock);
        return;
    }

    strncpy(e->host, host, sizeof(e->host) - 1);
    e->host[sizeof(e->host) - 1] = '\0';
    e->port    = port;
    e->expires = GetTickCount() + UPSTREAM_SESS_TTL_MS;
    e->used    = 1;

    LeaveCriticalSection(&g_upstream_sess_lock);
}

/* ------------------------------------------------------------------ */
/*  Parallel TLS handshakes                                            */
/* ------------------------------------------------------------------ */

static int parallel_handshake(SOCKET client, SOCKET server, const char *host,
                              int port,
                              mbedtls_ssl_context *bssl,
                              mbedtls_ssl_config  *bconf,
                              mbedtls_x509_crt    *bcert,
                              mbedtls_ssl_context *ussl,
                              mbedtls_ssl_config  *uconf)
{
    int ret;
    int b_done = 0, u_done = 0;
    int tcp_done = 0;
    int b_want = 'r';
    int u_want = 'r';
    int upstream_resumed = 0;
    int browser_resumed = 0;
    const unsigned char *cert_pem;
    size_t cert_pem_len;

    /* ------------------------------------------------------------------
     * Initialise all mbedTLS contexts up front so the caller can safely
     * free them on any failure path, including failures that happen
     * before the corresponding context is normally set up.
     * ------------------------------------------------------------------ */
    mbedtls_ssl_init(bssl);
    mbedtls_ssl_config_init(bconf);
    mbedtls_x509_crt_init(bcert);
    mbedtls_ssl_init(ussl);
    mbedtls_ssl_config_init(uconf);

    /* ------- Browser-side (server role) setup ------- */
    cert_pem = get_host_cert(host, &cert_pem_len);
    if (!cert_pem) {
        fprintf(stderr, "could not get cert for %s\n", host);
        return -1;
    }

    ret = mbedtls_x509_crt_parse(bcert, cert_pem, cert_pem_len);
    if (ret != 0) { print_mbedtls_error("parse browser cert", ret); return -1; }

    ret = mbedtls_ssl_config_defaults(bconf,
                                      MBEDTLS_SSL_IS_SERVER,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) { print_mbedtls_error("browser config_defaults", ret); return -1; }

    mbedtls_ssl_conf_min_version(bconf,
                                 MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_0);
    mbedtls_ssl_conf_ciphersuites(bconf, ie_compat_ciphersuites);
    mbedtls_ssl_conf_rng(bconf, locked_ctr_drbg_random, &g_ctr_drbg);
    mbedtls_ssl_conf_authmode(bconf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_own_cert(bconf, bcert, &g_server_key);

    mbedtls_ssl_conf_session_cache(bconf, &g_browser_cache,
                                   locked_browser_cache_get,
                                   locked_browser_cache_set);

    ret = mbedtls_ssl_setup(bssl, bconf);
    if (ret != 0) { print_mbedtls_error("browser ssl_setup", ret); return -1; }

    mbedtls_ssl_set_bio(bssl, (void *)(uintptr_t)client,
                        tls_send, tls_recv, NULL);

    /* ------- Upstream-side (client role) setup ------- */
    ret = mbedtls_ssl_config_defaults(uconf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) { print_mbedtls_error("upstream config_defaults", ret); return -1; }

    mbedtls_ssl_conf_rng(uconf, locked_ctr_drbg_random, &g_ctr_drbg);
    mbedtls_ssl_conf_authmode(uconf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_session_cache(uconf, &g_upstream_cache,
                                   locked_upstream_cache_get,
                                   locked_upstream_cache_set);

    ret = mbedtls_ssl_setup(ussl, uconf);
    if (ret != 0) { print_mbedtls_error("upstream ssl_setup", ret); return -1; }

    mbedtls_ssl_set_hostname(ussl, host);
    mbedtls_ssl_set_bio(ussl, (void *)(uintptr_t)server,
                        tls_send, tls_recv, NULL);

    /* Offer the cached session for this host:port, if any. Held under
     * the cache lock until mbedtls_ssl_set_session has copied the
     * session into ussl, so no other worker can evict it from under us. */
    {
        struct upstream_sess_entry *e;
        EnterCriticalSection(&g_upstream_sess_lock);
        e = find_upstream_sess(host, port);
        if (e) {
            ret = mbedtls_ssl_set_session(ussl, &e->sess);
            if (ret != 0) {
                LOG("  [upstream] cached session unusable; full handshake\n");
                mbedtls_ssl_session_free(&e->sess);
                e->used = 0;
            } else {
                LOG("  [upstream] offering cached session\n");
            }
        }
        LeaveCriticalSection(&g_upstream_sess_lock);
    }

    /* ------- Non-blocking mode ------- */
    {
        u_long nb = 1;
        ioctlsocket(client, FIONBIO, &nb);
    }

    /* ------- Drive both handshakes ------- */
    while (!b_done || !u_done) {
        fd_set rfds, wfds;
        struct timeval tv;
        int r;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        if (!tcp_done) {
            FD_SET(server, &wfds);
        } else if (!u_done) {
            if (u_want == 'r') FD_SET(server, &rfds);
            else               FD_SET(server, &wfds);
        }

        if (!b_done) {
            if (b_want == 'r') FD_SET(client, &rfds);
            else               FD_SET(client, &wfds);
        }

        tv.tv_sec  = 15;
        tv.tv_usec = 0;

        r = select(0, &rfds, &wfds, NULL, &tv);
        if (r <= 0) {
            fprintf(stderr, "handshake select timeout\n");
            goto fail;
        }

        /* ---- Upstream TCP connect completion ---- */
        if (!tcp_done && FD_ISSET(server, &wfds)) {
            int err = 0, errlen = sizeof(err);
            getsockopt(server, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
            if (err != 0) {
                fprintf(stderr, "upstream connect failed: %d\n", err);
                goto fail;
            }
            tcp_done = 1;

            ret = handshake_with_resume_check(ussl, &upstream_resumed);
            if (ret == 0) {
                u_done = 1;
                if (upstream_resumed)
                    LOG("  [upstream] %s / %s (resumed)\n",
                        mbedtls_ssl_get_version(ussl),
                        mbedtls_ssl_get_ciphersuite(ussl));
                else
                    LOG("  [upstream] %s / %s\n",
                        mbedtls_ssl_get_version(ussl),
                        mbedtls_ssl_get_ciphersuite(ussl));
            } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                u_want = 'r';
            } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                u_want = 'w';
            } else {
                print_mbedtls_error("upstream handshake", ret);
                goto fail;
            }
        }
        /* ---- Upstream TLS handshake progress ---- */
        else if (tcp_done && !u_done &&
                 (FD_ISSET(server, &rfds) || FD_ISSET(server, &wfds))) {
            ret = handshake_with_resume_check(ussl, &upstream_resumed);
            if (ret == 0) {
                u_done = 1;
                if (upstream_resumed)
                    LOG("  [upstream] %s / %s (resumed)\n",
                        mbedtls_ssl_get_version(ussl),
                        mbedtls_ssl_get_ciphersuite(ussl));
                else
                    LOG("  [upstream] %s / %s\n",
                        mbedtls_ssl_get_version(ussl),
                        mbedtls_ssl_get_ciphersuite(ussl));
            } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                u_want = 'r';
            } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                u_want = 'w';
            } else {
                print_mbedtls_error("upstream handshake", ret);
                goto fail;
            }
        }

        /* ---- Browser TLS handshake progress ---- */
        if (!b_done && (FD_ISSET(client, &rfds) || FD_ISSET(client, &wfds))) {
            ret = handshake_with_resume_check(bssl, &browser_resumed);
            if (ret == 0) {
                b_done = 1;
                if (browser_resumed)
                    LOG("  [browser]  %s / %s (resumed)\n",
                        mbedtls_ssl_get_version(bssl),
                        mbedtls_ssl_get_ciphersuite(bssl));
                else
                    LOG("  [browser]  %s / %s\n",
                        mbedtls_ssl_get_version(bssl),
                        mbedtls_ssl_get_ciphersuite(bssl));
            } else if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                b_want = 'r';
            } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                b_want = 'w';
            } else {
                print_mbedtls_error("browser handshake", ret);
                goto fail;
            }
        }
    }

    /* Refresh the upstream session cache. On a resumed handshake this
     * just extends the TTL; on a full handshake it stores the fresh
     * session for next time. */
    store_upstream_session(host, port, ussl);

    return 0;

fail:
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Diagnostic mode (client TLS to host:443)                           */
/* ------------------------------------------------------------------ */

static int diag_mode(const char *host)
{
    SOCKET s;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    if (tls_global_init() != 0) return 1;
    if (init_ca_and_server_key() != 0) return 1;
    init_ssl_session_caches();

    printf("retroproxhttps diagnostic: connecting to %s:443\n", host);
    fflush(stdout);

    s = connect_to(host, 443);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "Could not connect (WSA %d)\n", WSAGetLastError());
        return 1;
    }
    printf("  TCP connected.\n");

    if (tls_client_handshake(s, host, &ssl, &conf) != 0) {
        closesocket(s);
        return 1;
    }

    tls_print_peer("upstream", &ssl);

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    closesocket(s);
    printf("Handshake OK.\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Bidirectional TLS relay                                            */
/* ------------------------------------------------------------------ */

static void relay_tls(mbedtls_ssl_context *ssl_a,
                      mbedtls_ssl_context *ssl_b)
{
    unsigned char buf[BUFSIZE];
    SOCKET sa = (SOCKET)(uintptr_t)ssl_a->p_bio;
    SOCKET sb = (SOCKET)(uintptr_t)ssl_b->p_bio;
    int a_has_data = 0;
    int b_has_data = 0;

    for (;;) {
        while (a_has_data || mbedtls_ssl_get_bytes_avail(ssl_a) > 0) {
            int n = mbedtls_ssl_read(ssl_a, buf, sizeof(buf));
            if (n == MBEDTLS_ERR_SSL_WANT_READ ||
                n == MBEDTLS_ERR_SSL_WANT_WRITE) {
                a_has_data = 0;
                break;
            }
            if (n <= 0)
                goto done;

            {
                int off = 0;
                while (off < n) {
                    int w = mbedtls_ssl_write(ssl_b, buf + off, n - off);
                    if (w == MBEDTLS_ERR_SSL_WANT_READ ||
                        w == MBEDTLS_ERR_SSL_WANT_WRITE)
                        continue;
                    if (w <= 0)
                        goto done;
                    off += w;
                }
            }
        }

        while (b_has_data || mbedtls_ssl_get_bytes_avail(ssl_b) > 0) {
            int n = mbedtls_ssl_read(ssl_b, buf, sizeof(buf));
            if (n == MBEDTLS_ERR_SSL_WANT_READ ||
                n == MBEDTLS_ERR_SSL_WANT_WRITE) {
                b_has_data = 0;
                break;
            }
            if (n <= 0)
                goto done;

            {
                int off = 0;
                while (off < n) {
                    int w = mbedtls_ssl_write(ssl_a, buf + off, n - off);
                    if (w == MBEDTLS_ERR_SSL_WANT_READ ||
                        w == MBEDTLS_ERR_SSL_WANT_WRITE)
                        continue;
                    if (w <= 0)
                        goto done;
                    off += w;
                }
            }
        }

        {
            fd_set rfds;
            struct timeval tv;
            int r;

            FD_ZERO(&rfds);
            FD_SET(sa, &rfds);
            FD_SET(sb, &rfds);

            tv.tv_sec  = 60;
            tv.tv_usec = 0;

            r = select(0, &rfds, NULL, NULL, &tv);
            if (r <= 0)
                break;

            a_has_data = FD_ISSET(sa, &rfds) ? 1 : 0;
            b_has_data = FD_ISSET(sb, &rfds) ? 1 : 0;
        }
    }

done:
    return;
}

/* ------------------------------------------------------------------ */
/*  Plain HTTP passthrough (non-CONNECT proxy request)                 */
/* ------------------------------------------------------------------ */

static int parse_http_request(const char *req, char *host, size_t hostsz,
                              int *port, char *path, size_t pathsz)
{
    const char *p = req;
    const char *url, *url_end, *slash;

    while (*p && *p != ' ' && *p != '\r' && *p != '\n') p++;
    if (*p != ' ') return -1;
    p++;

    if (strncmp(p, "http://", 7) != 0) return -1;
    p += 7;
    url = p;

    url_end = url;
    while (*url_end && *url_end != ' ' && *url_end != '\r' && *url_end != '\n')
        url_end++;

    slash = url;
    while (slash < url_end && *slash != '/') slash++;

    {
        const char *colon = NULL;
        const char *q;
        size_t hlen;
        for (q = url; q < slash; q++) {
            if (*q == ':') { colon = q; break; }
        }
        if (colon) {
            hlen = (size_t)(colon - url);
            *port = atoi(colon + 1);
        } else {
            hlen = (size_t)(slash - url);
            *port = 80;
        }
        if (hlen == 0 || hlen >= hostsz) return -1;
        memcpy(host, url, hlen);
        host[hlen] = '\0';
    }

    if (slash < url_end) {
        size_t plen = (size_t)(url_end - slash);
        if (plen >= pathsz) return -1;
        memcpy(path, slash, plen);
        path[plen] = '\0';
    } else {
        if (pathsz < 2) return -1;
        path[0] = '/';
        path[1] = '\0';
    }

    return 0;
}

static int ci_prefix(const char *s, const char *prefix, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        char a = s[i];
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

static int rewrite_http_request(char *dst, size_t dstsz,
                                const char *src, int srclen,
                                const char *path)
{
    const char *p = src;
    const char *sp1, *sp2;
    size_t used = 0;

    sp1 = memchr(p, ' ', (size_t)srclen);
    if (!sp1) return -1;
    sp2 = memchr(sp1 + 1, ' ', (size_t)(src + srclen - (sp1 + 1)));
    if (!sp2) return -1;

    {
        size_t mlen = (size_t)(sp1 - p);
        size_t plen = strlen(path);
        if (used + mlen + 1 + plen + 12 > dstsz) return -1;
        memcpy(dst + used, p, mlen); used += mlen;
        dst[used++] = ' ';
        memcpy(dst + used, path, plen); used += plen;
        memcpy(dst + used, " HTTP/1.0\r\n", 11); used += 11;
    }

    p = sp2 + 1;
    while (p < src + srclen && *p != '\n') p++;
    if (p < src + srclen) p++;

    while (p < src + srclen) {
        const char *eol = p;
        int hlen;
        while (eol < src + srclen && *eol != '\n') eol++;
        hlen = (int)(eol - p);
        if (hlen > 0 && p[hlen - 1] == '\r') hlen--;

        if (hlen == 0) {
            if (used + 2 > dstsz) return -1;
            dst[used++] = '\r';
            dst[used++] = '\n';
            break;
        }

        if (ci_prefix(p, "Proxy-Connection:", 17) ||
            ci_prefix(p, "Connection:", 11)) {
            /* skip */
        } else {
            if (used + hlen + 2 > dstsz) return -1;
            memcpy(dst + used, p, hlen); used += hlen;
            dst[used++] = '\r';
            dst[used++] = '\n';
        }

        p = eol;
        if (p < src + srclen) p++;
    }

    return (int)used;
}

static void relay_plain(SOCKET a, SOCKET b)
{
    char buf[BUFSIZE];
    fd_set rfds;
    struct timeval tv;
    int n, r;

    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(a, &rfds);
        FD_SET(b, &rfds);

        tv.tv_sec  = 120;
        tv.tv_usec = 0;

        r = select(0, &rfds, NULL, NULL, &tv);
        if (r <= 0) break;

        if (FD_ISSET(a, &rfds)) {
            n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(b, buf, n, 0) != n) break;
        }
        if (FD_ISSET(b, &rfds)) {
            n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (send(a, buf, n, 0) != n) break;
        }
    }
}

static void handle_http_passthrough(SOCKET client,
                                    const char *req, int total, int hdr_end)
{
    char host[256];
    char path[2048];
    int port;
    SOCKET server;
    char newreq[REQMAX];
    int newlen;
    int prelen;

    if (parse_http_request(req, host, sizeof(host), &port,
                           path, sizeof(path)) != 0) {
        const char *err = "HTTP/1.0 400 Bad Request\r\n\r\n";
        send(client, err, strlen(err), 0);
        return;
    }

    LOG("HTTP  %s:%d%s\n", host, port, path);

    server = connect_to(host, port);
    if (server == INVALID_SOCKET) {
        const char *err = "HTTP/1.0 502 Bad Gateway\r\n\r\n";
        send(client, err, strlen(err), 0);
        return;
    }

    newlen = rewrite_http_request(newreq, sizeof(newreq), req, hdr_end, path);
    if (newlen < 0) {
        const char *err = "HTTP/1.0 400 Bad Request\r\n\r\n";
        send(client, err, strlen(err), 0);
        closesocket(server);
        return;
    }

    if (send(server, newreq, newlen, 0) != newlen) {
        closesocket(server);
        return;
    }

    prelen = total - hdr_end;
    if (prelen > 0) {
        if (send(server, req + hdr_end, prelen, 0) != prelen) {
            closesocket(server);
            return;
        }
    }

    relay_plain(client, server);

    closesocket(server);
}

/* ------------------------------------------------------------------ */
/*  Worker thread                                                      */
/*                                                                     */
/*  One worker per accepted client connection. Owns every mbedTLS      */
/*  context for that connection, performs the entire request           */
/*  lifecycle, and closes both sockets when done. No global state is   */
/*  held across blocking calls except the locks documented at the top. */
/* ------------------------------------------------------------------ */

struct worker_arg {
    SOCKET client;
};

static void worker_thread(void *param)
{
    struct worker_arg *arg = (struct worker_arg *)param;
    SOCKET client = arg->client;
    free(arg);

    {
        char req[REQMAX];
        int total = 0, hdr_end = 0;
        char host[256];
        int port;
        SOCKET server;
        const char *ok;

        mbedtls_ssl_context cli_ssl, srv_ssl;
        mbedtls_ssl_config cli_conf, srv_conf;
        mbedtls_x509_crt   srvcert;

        while (total < REQMAX - 1) {
            int n = recv(client, req + total, REQMAX - 1 - total, 0);
            int i;
            if (n <= 0) break;
            total += n;
            req[total] = '\0';
            for (i = 0; i + 3 < total; i++) {
                if (req[i]=='\r' && req[i+1]=='\n' &&
                    req[i+2]=='\r' && req[i+3]=='\n') { hdr_end = i + 4; break; }
            }
            if (hdr_end) break;
        }

        if (hdr_end == 0) {
            const char *err = "HTTP/1.0 400 Bad Request\r\n\r\n";
            send(client, err, strlen(err), 0);
            goto done;
        }

        if (parse_connect(req, host, sizeof(host), &port) != 0) {
            handle_http_passthrough(client, req, total, hdr_end);
            goto done;
        }

        LOG("\nCONNECT %s:%d\n", host, port);

        server = start_nonblocking_connect(host, port);
        if (server == INVALID_SOCKET) {
            const char *err = "HTTP/1.0 502 Bad Gateway\r\n\r\n";
            send(client, err, strlen(err), 0);
            goto done;
        }

        ok = "HTTP/1.0 200 Connection Established\r\n\r\n";
        send(client, ok, strlen(ok), 0);

        if (parallel_handshake(client, server, host, port,
                               &srv_ssl, &srv_conf, &srvcert,
                               &cli_ssl, &cli_conf) != 0) {
            mbedtls_ssl_free(&srv_ssl);
            mbedtls_ssl_config_free(&srv_conf);
            mbedtls_x509_crt_free(&srvcert);
            mbedtls_ssl_free(&cli_ssl);
            mbedtls_ssl_config_free(&cli_conf);
            closesocket(server);
            goto done;
        }

        LOG("  [browser]  OK\n");
        relay_tls(&srv_ssl, &cli_ssl);

        mbedtls_ssl_close_notify(&srv_ssl);
        mbedtls_ssl_close_notify(&cli_ssl);

        mbedtls_ssl_free(&srv_ssl);
        mbedtls_ssl_config_free(&srv_conf);
        mbedtls_x509_crt_free(&srvcert);

        mbedtls_ssl_free(&cli_ssl);
        mbedtls_ssl_config_free(&cli_conf);

        closesocket(server);
    }

done:
    closesocket(client);
    /* _beginthread-owned threads must call _endthread to clean up;
     * returning from the entry point also does this under MinGW,
     * but being explicit is safer across CRT versions. */
    _endthread();
}

/* ------------------------------------------------------------------ */
/*  Proxy mode                                                         */
/* ------------------------------------------------------------------ */

static int proxy_mode(void)
{
    SOCKET listener;
    struct sockaddr_in addr;
    int yes = 1;

    if (tls_global_init() != 0) return 1;
    if (init_ca_and_server_key() != 0) return 1;
    init_ssl_session_caches();

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET) die("socket");

    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0) die("bind");
    if (listen(listener, 16) != 0) die("listen");

    printf("retroproxhttps MITM proxy listening on 127.0.0.1:%d\n", LISTEN_PORT);
    printf("Install %s as a trusted root CA, then set your browser's\n",
           CA_CRT_FILE);
    printf("HTTP proxy to 127.0.0.1:%d.\n", LISTEN_PORT);
    printf("(threaded: one worker per connection)\n");
    fflush(stdout);

    for (;;) {
        struct sockaddr_in cli;
        int clilen = sizeof(cli);
        SOCKET client;
        struct worker_arg *arg;

        client = accept(listener, (struct sockaddr *)&cli, &clilen);
        if (client == INVALID_SOCKET) continue;
        set_nodelay(client);

        arg = (struct worker_arg *)malloc(sizeof(*arg));
        if (!arg) {
            closesocket(client);
            continue;
        }
        arg->client = client;

        if (_beginthread(worker_thread, 0, arg) == (uintptr_t)-1) {
            /* Thread creation failed — clean up and drop the connection. */
            fprintf(stderr, "worker thread creation failed\n");
            closesocket(client);
            free(arg);
            continue;
        }
    }

    closesocket(listener);
    return 0;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    WSADATA wsa;
    int rc;

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    if (argc > 1)
        rc = diag_mode(argv[1]);
    else
        rc = proxy_mode();

    WSACleanup();
    return rc;
}
