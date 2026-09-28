# RetroProxHTTPS — Compile Guide

A local HTTPS→HTTP MITM proxy that runs natively inside Windows 9x/XP.

## What It Does

RetroProxHTTPS listens on `127.0.0.1:8080` and handles two kinds of
proxy requests:

1. **HTTPS (CONNECT)** — terminates TLS locally using per-host
   certificates signed by a bundled root CA, and opens a modern TLS
   session to the real server. Decrypted HTTP is relayed between the
   two sessions.
   - Browser side accepts SSL 3.0 / TLS 1.0 with RC4 or 3DES
     (IE 5.x / Netscape 4.x compatible).
   - Upstream side negotiates TLS 1.2 with the real server.
   - Per-host certs are generated on demand and cached for the lifetime
     of the process.
   - Cert validity is derived from the local clock at generation time
     (`notBefore` = now, `notAfter` = now + 20 years).
   - Leaf certs are encoded for maximum compatibility with old clients:
     the CN is emitted as `PrintableString` (IE 5.01 and Netscape 4.x
     cannot decode `UTF8String` in certificate names), and the
     `subjectAltName` extension carries the correct DER-encoded OID.
   - TLS session resumption is used on both sides to speed up reconnects.

2. **Plain HTTP** — rewrites the request line from proxy form
   (`GET http://host/path`) to origin form (`GET /path`), strips
   `Proxy-Connection:` and `Connection:` headers, and forwards.

DNS lookups are cached for 5 minutes. Both TLS handshakes for a single
connection run in parallel, and each connection is handled by its own
worker thread, so a slow relay on one connection no longer blocks the
accept loop.

On first run the proxy generates a unique 2048-bit root CA, writes its
private key to the registry under `HKCU\Software\RetroProxHTTPS\CAKey`,
and emits `ca.crt` next to the executable for the user to install. Each
machine gets its own CA — no shared secret ships with the binary. The
per-host signing key is a fresh 1024-bit RSA key generated in memory on
each run and never persisted.

### Concurrency model

The main thread runs only an `accept()` loop. Every accepted connection
is handed to its own worker thread, which runs the entire request
lifecycle: parse the CONNECT, open the upstream socket, run both TLS
handshakes, relay bytes in both directions, and close the sockets.

This matters because the previous single-threaded design spent most of
its wall-clock time blocked on I/O. While a relay was running, the
accept loop was hostage to it, so IE's parallel-connection page loads
(2–4 CONNECTs per page) queued up behind each other. The threaded
version accepts them all immediately; handshakes overlap at the I/O
level, and the page finishes when the slowest single handshake finishes
rather than when the sum of all four does.

Threads are created with `_beginthread` and terminated with
`_endthread` from `<process.h>`. **No extra link library is needed** —
both routines live in `msvcrt.dll`, and `<process.h>` is header-only.
The link line stays exactly as before.

Shared state is protected by six `CRITICAL_SECTION`s:

| Lock | Guards |
|---|---|
| `g_log_lock` | All `printf`/`fflush` via the `LOG()` macro |
| `g_drbg_lock` | The shared `mbedtls_ctr_drbg_context` |
| `g_cert_cache_lock` | The per-host certificate cache |
| `g_upstream_sess_lock` | The per-host upstream session cache |
| `g_browser_cache_lock` | mbedTLS's browser-side session cache |
| `g_upstream_cache_lock` | mbedTLS's upstream-side session cache |

The lock order throughout the file is strictly **cache → DRBG**. The
DRBG lock is a leaf: nothing that holds it calls out to anything else
that takes a lock. No cyclic dependency exists, so no deadlock is
possible. Each lock is held only for the duration of one operation and
never across a blocking socket call.

`g_ca_key`, `g_server_key`, and `g_entropy` are read-only after
`init_ca_and_server_key()` returns, so they need no locking. The DNS
cache is intentionally left unlocked; concurrent writes can only
duplicate an entry, never corrupt one.

### Performance notes for slow CPUs

On a Pentium Pro class machine the RSA private operation dominates both
key generation and per-connection cost. Three measures keep it
tolerable:

- **1024-bit server key** instead of 2048. Nothing on Win9x verifies
  key strength; the private op is ~4× cheaper.
- **`MBEDTLS_HAVE_ASM`** enabled in mbedTLS. Uses the i386 inline
  assembly big-integer routines for RSA/ECDHE/DH — 2–4× faster than
  the pure-C path.
- **Upstream session resumption** across `CONNECT`s to the same host.
  The second and later connections skip ECDHE and certificate
  verification entirely and go straight to the abbreviated handshake.

Threading adds one more win: CPU-bound work on one connection now
overlaps with I/O waits on another. On a single-core CPU it doesn't
give you any more raw compute, but it does stop the I/O waits of one
connection from idling the CPU when another has work to do.

---

## Host Requirements (build machine)

- **Linux** (developed on Ubuntu 24.04 and later).
- **MinGW-w64 cross-compiler** targeting 32-bit Windows with the
  `msvcrt` C runtime:
  - `gcc-mingw-w64-i686-win32`
  - `g++-mingw-w64-i686-win32`
- **CMake** (any recent version).
- **Git / wget / tar** (to fetch sources).

Install on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install gcc-mingw-w64-i686-win32 g++-mingw-w64-i686-win32 \
                 cmake
```

Then make the `-win32` variants the default for the generic
`i686-w64-mingw32-*` names:

```bash
sudo update-alternatives --set i686-w64-mingw32-gcc /usr/bin/i686-w64-mingw32-gcc-win32
sudo update-alternatives --set i686-w64-mingw32-g++ /usr/bin/i686-w64-mingw32-g++-win32
```

Verify:

```bash
i686-w64-mingw32-gcc -dumpmachine    # → i686-w64-mingw32
i686-w64-mingw32-gcc --version       # → GCC 13-win32 (or similar)
```

The `-win32` variant links against the ancient `msvcrt.dll` instead of
the modern UCRT. This is essential for Win9x compatibility.

## Component Breakdown

| Component | Version | Purpose |
|---|---|---|
| **mbedTLS** | **2.25.0** | TLS library. Last branch with working SSL 3.0 support. |
| **MinGW-w64 GCC** | 13.x `-win32` | Cross-compiler for the target. |
| **proxy.c** | (this project) | The proxy itself. |

**Why mbedTLS 2.25 specifically?** It's the last release that supports
`MBEDTLS_SSL_PROTO_SSL3` as a functional build option. mbedTLS 2.26
deprecated it, 2.28 removed the code paths, and 3.x/4.x are completely
unusable for pre-TLS-1.0 clients. 2.25 is also the last branch with a
working `CryptGenRandom` fallback for Win9x entropy.

The public `mbedtls_ssl_session_reused()` accessor was added in 2.28;
on 2.25 the proxy uses the internal `ssl->handshake->resume` flag
directly (via `mbedtls/ssl_internal.h`) in a custom handshake driver.

mbedTLS 2.25 was not built with `MBEDTLS_THREADING_C`, so its session
caches are not thread-safe by themselves. The proxy wraps every cache
access with its own `CRITICAL_SECTION`, which is simpler than enabling
mbedTLS's threading layer (which would require providing the
`mbedtls_threading_set_alt()` primitive set).

---

## Step-by-Step Build

### 1. Fetch mbedTLS

```bash
wget https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.25.0.tar.gz
tar -xf v2.25.0.tar.gz
```

### 2. Configure mbedTLS for the target

Edit `mbedtls-2.25.0/include/mbedtls/config.h`. Uncomment:

```c
/* SSL 3.0 support (required for IE 5.x / Netscape 4.x) */
#define MBEDTLS_SSL_PROTO_SSL3
#define MBEDTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO

/* X.509 write support (for per-host cert generation) */
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_PK_WRITE_C

/* TLS session resumption */
#define MBEDTLS_SSL_CACHE_C
#define MBEDTLS_SSL_SESSION_TICKETS

/* Performance: i386 inline-assembly big-integer routines.
 * This is the single biggest CPU win on 32-bit x86 and is required
 * for the proxy to feel usable on a Pentium Pro or faster. */
#define MBEDTLS_HAVE_ASM

/* Performance: precomputed fixed-point tables for NIST elliptic
 * curves. Speeds up the upstream ECDHE handshake significantly. */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM
```

Also verify these are enabled (they are by default in 2.25):

```c
#define MBEDTLS_ARC4_C
#define MBEDTLS_DES_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_FS_IO
#define MBEDTLS_ECP_NIST_OPTIM    /* on by default; leave enabled */
```

Leave `MBEDTLS_THREADING_C` **disabled**. The proxy supplies its own
locking around the parts of mbedTLS that need it; enabling the
threading layer would require wiring up `mbedtls_threading_set_alt()`
to Win32 primitives, which is unnecessary.

### 3. Patch `platform.c` to remove the `_vsnprintf_s` dependency

Edit `mbedtls-2.25.0/library/platform.c`. Find the function
`mbedtls_platform_win32_vsnprintf()` and change:

```c
#if defined(_TRUNCATE)
    ret = vsnprintf_s(s, n, _TRUNCATE, fmt, arg);
```

to:

```c
#if 0
    ret = vsnprintf_s(s, n, _TRUNCATE, fmt, arg);
```

This forces mbedTLS to use plain `vsnprintf`, which Win9x's `msvcrt.dll`
exports. Without this patch, the resulting binary will refuse to start
with a "_vsnprintf_s: linked to missing export" error.

### 4. Create the CMake toolchain file

Save as `win9x-toolchain.cmake`:

```cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR i686)

set(CMAKE_C_COMPILER   /usr/bin/i686-w64-mingw32-gcc-win32)
set(CMAKE_CXX_COMPILER /usr/bin/i686-w64-mingw32-g++-win32)
set(CMAKE_RC_COMPILER  /usr/bin/i686-w64-mingw32-windres)

set(WIN9X_DEFS "-D_WIN32_WINNT=0x0400 -DWINVER=0x0400 -D__MSVCRT_VERSION__=0x0400 -D__USE_MINGW_ANSI_STDIO=0 -D_CRT_SECURE_NO_WARNINGS")

set(CMAKE_C_FLAGS   "-march=pentium -m32 -O3 -funroll-loops -std=gnu99 ${WIN9X_DEFS}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "-march=pentium -m32 -O3 -funroll-loops ${WIN9X_DEFS}"          CACHE STRING "" FORCE)

set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc" CACHE STRING "" FORCE)

set(CMAKE_FIND_ROOT_PATH /usr/i686-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

Notes on the flags:

- `-march=pentium`: safe baseline for Pentium Pro. Use
  `-march=pentium3` for Coppermine-and-later, or `-march=i686` if you
  want the broadest possible binary. GCC schedules best for the target
  you actually name.
- `-D_WIN32_WINNT=0x0400`: target Windows 95/NT4-era APIs. This is what
  makes mbedTLS use the pre-Vista `CryptGenRandom` entropy path.
- `-D__MSVCRT_VERSION__=0x0400`: tell the CRT headers to target the
  Win95-era `msvcrt.dll`.
- `-D__USE_MINGW_ANSI_STDIO=0`: force MinGW to use its own `vsnprintf`
  rather than mapping to the secure-CRT variant.
- `-std=gnu99`: required by mbedTLS 2.25.
- `-O3 -funroll-loops`: matters a lot for the software crypto primitives.

Note: threading does not require `-pthread` or any other flag. Win32
threads are always available; `_beginthread` and the `CRITICAL_SECTION`
routines live in `msvcrt.dll` and `kernel32.dll` respectively, both of
which every Win9x binary links against already.

### 5. Build mbedTLS as static libraries

```bash
mkdir build-mbedtls-225 && cd build-mbedtls-225

cmake \
  -DCMAKE_TOOLCHAIN_FILE=../win9x-toolchain.cmake \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
  -DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
  -DENABLE_PROGRAMS=OFF \
  -DENABLE_TESTING=OFF \
  -DENABLE_ZLIB_SUPPORT=OFF \
  ../mbedtls-2.25.0

make -j$(nproc)
```

The `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` flag is required because modern
CMake refuses to honor mbedTLS's `cmake_minimum_required(VERSION 2.x)` line.

You should end up with three static archives:

```
build-mbedtls-225/library/libmbedtls.a
build-mbedtls-225/library/libmbedx509.a
build-mbedtls-225/library/libmbedcrypto.a
```

### 6. Build the proxy

```bash
i686-w64-mingw32-gcc-win32 \
    -march=pentium -m32 -O3 -funroll-loops \
    -D_WIN32_WINNT=0x0400 -DWINVER=0x0400 \
    -D__MSVCRT_VERSION__=0x0400 \
    -D__USE_MINGW_ANSI_STDIO=0 \
    -D_CRT_SECURE_NO_WARNINGS \
    -static -static-libgcc \
    -I mbedtls-2.25.0/include \
    -o proxy.exe proxy.c \
    -L build-mbedtls-225/library \
    -lmbedtls -lmbedx509 -lmbedcrypto \
    -lws2_32 -ladvapi32
```

- `-lws2_32` — Winsock 2.
- `-ladvapi32` — registry calls that persist the CA private key.
- Threading needs no extra library; `_beginthread`/`_endthread` come
  from `msvcrt.dll` and are pulled in automatically.

**Sanity-check the imports before deploying:**

```bash
i686-w64-mingw32-objdump -p proxy.exe | grep "DLL Name"
```

Expected:

```
DLL Name: ADVAPI32.dll
DLL Name: KERNEL32.dll
DLL Name: msvcrt.dll
DLL Name: WS2_32.dll
```

If you see `ucrtbase.dll`, `kernelbase.dll`, or `api-ms-win-crt-*.dll`,
the compiler is not the `-win32` variant. Re-run the
`update-alternatives` step from the Host Requirements section.

Check that `_vsnprintf_s` is not in the import table:

```bash
i686-w64-mingw32-objdump -p proxy.exe | grep -i vsnprintf
```

You should see `_vsnprintf` (no `_s`) or nothing at all.

---

## Deployment to Win9x

1. Copy `proxy.exe` to the Win9x VM. That's the only file needed.

2. Open a DOS prompt and run:

   ```
   proxy.exe
   ```

   On first run you'll see:

   ```
   === First run: generating root CA ===
   Wrote ca.crt.
     generating 1024-bit server key (in memory)...

   ================================================================
     FIRST-RUN SETUP COMPLETE

     A root CA certificate has been written to:
       ca.crt

     Install it in your browser's Trusted Root Certification
     Authorities store, then restart the browser:

       Internet Explorer:
         Tools -> Internet Options -> Content -> Certificates
         -> Import -> Trusted Root Certification Authorities
         -> select ca.crt

     The CA private key is stored in the registry at:
       HKCU\Software\RetroProxHTTPS\CAKey
     and will be reused automatically on future runs.
   ================================================================

   RetroProxHTTPS MITM proxy listening on 127.0.0.1:8080
   Install ca.crt as a trusted root CA, then set your browser's
   HTTP proxy to 127.0.0.1:8080.
   (threaded: one worker per connection)
   ```

   On a Pentium Pro 100 MHz the CA keygen step takes roughly a minute
   the very first time. The 1024-bit server keygen that follows takes
   another 5–10 seconds on the same hardware.

3. Install `ca.crt`:
   - Double-click `ca.crt` → Install Certificate.
   - Choose **Trusted Root Certification Authorities**.
   - Confirm the security warning (the CA is self-signed, so Windows
     will warn).
   - Close and restart IE.

4. Configure IE's proxy:
   - **Tools → Internet Options → Connections → LAN Settings**
   - ☑ Use a proxy server
   - Address: `127.0.0.1`, Port: `8080`

5. Visit `https://example.com/` — it should render normally, and the
   proxy log shows per-host cert generation, both handshakes, and the
   relay. If IE opens several parallel connections (it will, for any
   page with multiple subresources), you should see the `CONNECT` lines
   appear back-to-back within milliseconds of the page request rather
   than one after another as each previous relay finishes.

Subsequent runs of `proxy.exe` print:

```
CA key loaded from registry.
  generating 1024-bit server key (in memory)...
CA + server key ready; dynamic cert generation enabled.
```

and skip the first-run banner entirely.

### Uninstall

- Delete `proxy.exe` and `ca.crt`.
- Delete the registry key:
  ```
  HKCU\Software\RetroProxHTTPS
  ```
- Remove the CA from IE's trusted root store via
  **Tools → Internet Options → Content → Certificates**.
- Turn off the proxy setting.

---

## Certificate encoding

The proxy generates two kinds of certificates:

- The **root CA**, written once to `ca.crt`. Its DN uses `UTF8String`
  as produced by mbedTLS's default name parser. That's fine — no client
  reads the CA's name for a hostname match, and modern browsers prefer
  the encoding.
- The **leaf certificate** for each host. Two encoding details matter
  here and are handled by the code:
  - The subject CN is retagged as `PrintableString` via
    `force_printable_string()` after `set_subject_name()`. IE 5.01 and
    Netscape 4.x cannot decode `UTF8String` in cert names; they fall
    through to the `O=` attribute, compare `RetroProxHTTPS` against the
    hostname, and show a "name on the security certificate does not
    match the name of the site" prompt. `PrintableString` fixes that on
    every client back to the late 90s and remains valid X.509.
  - The `subjectAltName` extension is encoded by hand because mbedTLS
    2.25 has no `set_subject_alt_name()` helper. The OID is passed as
    the raw DER bytes `0x55 0x1D 0x11` (2.5.29.17), **not** as a
    dotted-decimal string. Passing the string produces a non-standard
    extension under a garbage OID that modern browsers silently ignore
    and treat as a missing SAN.

If you ever see "name mismatch" warnings reappear on a freshly built
binary, the cause is almost always one of those two. Verify with:

```bash
openssl x509 -in /path/to/generated.pem -text -noout
```

and confirm the subject shows `PrintableString` and the SAN extension
contains `DNS:<hostname>`.

### Dynamic validity

`build_validity_dates()` calls `GetSystemTime()` (which returns UTC,
matching what X.509 stores) and formats the result as
`YYYYMMDDHHMMSS`. `notAfter` is `notBefore` with `wYear + 20`. Both the
CA and every leaf cert use this. No date is hard-coded, so the proxy
keeps working past 2036 without a rebuild.

The cert cache holds generated PEMs for the lifetime of the process,
keyed on hostname only, guarded by `g_cert_cache_lock`. Restarting
`proxy.exe` is enough to force regeneration after a code change; you
don't need to reinstall `ca.crt` unless the CA private key in the
registry was lost.

---

## Diagnostic Mode

```
proxy.exe <hostname>
```

Connects to `hostname:443`, performs a client-side TLS handshake, and
prints:

```
retroproxhttps diagnostic: connecting to example.com:443
  TCP connected.
  [upstream] TLSv1.2 / TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256
  [upstream] cert: CN=example.com
Handshake OK.
```

Useful for verifying that mbedTLS works on the target before involving
the browser. Note that diagnostic mode still calls
`init_ca_and_server_key()`, so the first invocation on a fresh machine
will generate the CA.

Diagnostic mode runs in the main thread before any workers exist, so
there is no concurrency to worry about. It still goes through the
locked wrappers, which are harmless when nothing else is contending.

---

## Ciphersuite selection

The proxy offers a deliberately short list to the browser:

```
TLS_RSA_WITH_RC4_128_MD5          (0x0004, listed first)
TLS_RSA_WITH_RC4_128_SHA          (0x0005)
TLS_RSA_WITH_3DES_EDE_CBC_SHA     (0x000A)
```

This is the intersection of what IE 5.x, Netscape 4.x, and IE 6/7 on
Windows 9x / 2000 are willing to negotiate. Every suite is static-RSA,
so no Diffie-Hellman modexp runs on the server side. AES suites are
omitted because pre-IE-7 clients don't offer them and there's no point
paying for the selection work.

The upstream side accepts whatever the real server offers. Modern
hosts land on TLS 1.2 with ECDHE and AES-GCM; the proxy does not
constrain the upstream list.

If you want the browser side to prefer RC4 over 3DES even when the
client lists 3DES first, add:

```c
mbedtls_ssl_conf_preference_order(bconf, MBEDTLS_SSL_SERVER_PREFERENCE);
```

right after `mbedtls_ssl_conf_ciphersuites()`. This is a small win
(50–100 ms per CONNECT on a PPro) and is not enabled by default
because some clients behave better when they get their own first
choice.

---

## File Layout

```
retroproxhttps/
├── proxy.c                    ← main program
├── win9x-toolchain.cmake
├── mbedtls-2.25.0/            ← patched source tree
├── build-mbedtls-225/
│   └── library/
│       ├── libmbedcrypto.a
│       ├── libmbedx509.a
│       └── libmbedtls.a
└── proxy.exe                  ← build output

# Generated at runtime on the target machine:
├── ca.crt                     ← user installs this in the browser
└── HKCU\Software\RetroProxHTTPS\CAKey  ← CA private key (registry)
```

---

## Registry Layout

The CA private key is stored as a `REG_SZ` value:

```
HKEY_CURRENT_USER
└── Software
    └── RetroProxHTTPS
        └── CAKey = "-----BEGIN RSA PRIVATE KEY-----\n...\n"
```

The value holds the full PEM text of the RSA-2048 CA key. On Win9x the
per-value size limit comfortably accommodates the ~1.7 KB PEM payload.

If the registry key is deleted, the next run generates a fresh CA and
overwrites `ca.crt`. The user will need to reinstall it — the previous
one is no longer trusted because the underlying key has changed.

Note that the per-run 1024-bit server key is **not** stored anywhere.
It is regenerated from the entropy pool every time `proxy.exe` starts
and exists only for the lifetime of the process.

---

## Porting and threading notes

- **Win9x thread creation.** `_beginthread` on original Windows 95 RTM
  (1995) had a known bug that could leak a CRT thread slot if the
  thread exited very quickly. OSR2 (1996) and later fixed it. IE 5.01
  requires 95 OSR2 or later, so any machine that can run the browser
  can run the threaded proxy. If you ever test on vanilla 95 RTM and
  see sporadic `worker thread creation failed` messages after thousands
  of connections, that's the bug.
- **Stack size.** Each worker gets the Win32 default of 1 MB reserved
  (only a fraction committed). With IE's typical 2–4 concurrent
  connections the committed total is well under 1 MB. Even 16
  simultaneous workers would cost well under 100 MB of address space,
  which is trivial on the 256 MB configuration.
- **Context switches.** On a single-core CPU, the scheduler switches
  between workers whenever one blocks on I/O. The switch itself is a
  few microseconds on a PPro. Handshake and relay code spends nearly
  all its time either executing CPU-bound crypto or blocked in
  `select()`, so the actual switch rate is low and the overhead is
  negligible compared to the work being done.
