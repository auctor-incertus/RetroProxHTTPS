> [!NOTE]
> This repository has been vibe-coded with DeepSeek.

# RetroProxHTTPS

A local HTTPS MITM proxy that runs natively on Windows 9x and
other legacy Windows versions, letting outdated browsers reach modern
HTTPS sites. Works on Pentium Pro+.

Built with [mbedTLS 2.25](https://github.com/Mbed-TLS/mbedtls), the last
release that supports the protocols and ciphers old browsers actually
speak.

## How it works

RetroProxHTTPS listens on `127.0.0.1:8080` as a local HTTP proxy. When
your browser connects:

- **HTTPS (CONNECT)** — the proxy terminates the browser's TLS session
  locally using a per-host certificate it generates on the fly, and opens
  a fresh modern TLS session to the real server. Decrypted HTTP is
  relayed between the two.
- **Plain HTTP** — the request is rewritten from proxy form to origin
  form and forwarded unchanged.

Every accepted connection gets its own worker thread, so a slow relay
on one connection never blocks the next one. IE opens two to four
parallel connections per page; the proxy picks them all up immediately
and lets the handshakes overlap, which is the difference between a page
load that finishes when the slowest handshake finishes and one that
waits for the sum of all of them.

On the first run, the proxy generates a unique root CA for your
machine, stores the private key in the Windows registry under
`HKCU\Software\RetroProxHTTPS\CAKey`, and writes `ca.crt` next to
`proxy.exe` for you to install into the browser's trust store. Every
machine gets its own CA; no shared key ships with the binary. The
per-host signing key used during operation is a fresh 1024-bit RSA key
generated in memory on each launch and never written to disk.

## Quick start

1. Copy `proxy.exe` to the legacy Windows machine.

2. Run it:

   On first run it will print instructions and write `ca.crt` next to
   itself.

3. Install `ca.crt` into the browser:
   - Double-click `ca.crt` → Install Certificate.
   - Restart the browser.

4. Configure the browser to use the proxy:
   - **Tools → Internet Options → Connections → LAN Settings**
   - ☑ Use a proxy server
   - Address: `127.0.0.1`, Port: `8080`

5. Visit any HTTPS site. The padlock should be present.

To stop using the proxy, turn off the browser's proxy setting and
close `proxy.exe`. To fully uninstall, delete `proxy.exe` and `ca.crt`,
remove the registry key `HKCU\Software\RetroProxHTTPS`, and remove the CA
from the browser's certificate store.

## Demonstration

![https://spacejam.com/1996 working on Internet Explorer 5.5 using RetroProxHTTPS in Windows 95](images/screenshot.png)
https://spacejam.com/1996 working on Internet Explorer 5.5 using RetroProxHTTPS in Windows 95

## Target requirements

- Windows 95 OSR2, 98, 98SE, Me, NT4, 2000, or XP.
- **Winsock 2** — bundled with 98 and later. Install the Winsock 2
  Update on Windows 95 (required because the proxy uses it).
- **Internet Explorer 5.5** or any browser that offers SSL 3.0.

Browser settings that work:

- **Tools → Internet Options → Advanced → Security:**
  - ☐ Use SSL 2.0
  - ☑ Use SSL 3.0
  - ☑ Use TLS 1.0
- **Tools → Internet Options → Connections → LAN Settings:**
  - ☑ Use a proxy server: `127.0.0.1`, port `8080`
  - ☐ Bypass proxy for local addresses
  - ☐ Automatically detect settings

SSL 2.0 must be **off**. When it is on, IE sends a genuine SSL 2.0
ClientHello that the proxy cannot negotiate with, and the connection
fails.

Turning off "Automatically detect settings" is strongly recommended.
When it is on, IE tries WPAD before falling back to your manual proxy,
which can cost several seconds on the first page of a browsing session.

## Performance

On a Pentium Pro 100 MHz the dominant cost is RSA. The proxy is tuned
to keep it manageable:

- A fresh 1024-bit RSA server key is generated in memory on every
  launch (5–10 seconds on the PPro). Nothing on Win9x checks key
  strength, and the 1024-bit private op is roughly four times cheaper
  than 2048.
- The upstream leg uses TLS 1.2 with session resumption. Repeat
  connections to the same host skip ECDHE and certificate verification
  entirely.
- mbedTLS is built with `MBEDTLS_HAVE_ASM` and
  `MBEDTLS_ECP_FIXED_POINT_OPTIM`, which use i386 inline assembly and
  precomputed elliptic-curve tables. Combined they roughly halve the
  cost of every handshake.

The remaining wall time on a page load is usually dominated by IE 5.01
itself opening one HTTP/1.0 request per TCP connection. That's the
floor, and it's not something the proxy can fix.

## Building from source

See [`COMPILE.md`](COMPILE.md). You will need a Linux build machine
with the MinGW-w64 cross-compiler and CMake.

## Diagnostic mode

```
proxy.exe <hostname>
```

Connects to `<hostname>:443`, performs a TLS handshake, and prints the
negotiated version, cipher, and server certificate subject. Useful for
verifying mbedTLS works on the target machine before involving a
browser.

## Security

**Read this before using the proxy on any machine you care about.**

RetroProxHTTPS is a TLS man-in-the-middle by design. The browser is
configured to trust a locally-generated CA, and the proxy uses that
trust to impersonate any HTTPS site. That is the whole point of the
project, but it has real consequences.

### What this proxy does

- Terminates the browser's TLS session locally and opens a second TLS
  session to the real server. Every byte of HTTPS traffic passes
  through the proxy in plaintext during the relay.

### What this proxy intentionally weakens

To talk to old browsers, the proxy accepts:

- **SSL 3.0** — vulnerable to POODLE.
- **TLS 1.0** — deprecated by every standards body.
- **RC4** cipher suites — biased keystream, broken since 2013.
- **3DES** cipher suites — Sweet32 birthday attack.
- **SHA-1** signed certificates — collision-broken.

The upstream leg (proxy → real server) uses modern TLS 1.2 with
ChaCha20-Poly1305 or AES-GCM. The weak ciphers are only on the
loopback leg between the browser and the proxy.

### Trust model

- The CA private key is stored in the current user's registry hive. Any
  process running as that user can read it and sign certificates for
  arbitrary hostnames.
- The browser will accept those certificates because the CA is in its
  trusted root store.

### Do not

- Do **not** bind the proxy to a non-loopback interface. The current
  code listens only on `127.0.0.1`, which is correct.
- Do **not** install the generated `ca.crt` on a modern machine or on
  any machine that handles sensitive data.
- Do **not** use the proxy for banking, email, or anything else where a
  credential compromise would matter.
- Do **not** expose port `8080` to any network.

### Do

- Use only in an isolated VM or a dedicated retro machine.
- Regenerate the CA (delete the registry key) if you suspect the key
  was read by something you don't trust.
- Shut the proxy down when you're not actively browsing.

## Related projects

- [ProxHTTPSProxyMII](https://github.com/wheever/ProxHTTPSProxyMII) —
  the original inspiration. Runs on Windows XP, uses a single
  pre-generated certificate, and requires .NET.

## Status

Tested working on Windows 95 OSR2 with Internet Explorer 5.5.
