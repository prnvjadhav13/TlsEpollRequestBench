# TlsEpollRequestBench

TlsEpollRequestBench is a C++23/Linux systems-programming project for learning
how to add production-oriented TLS protection to a scalable, nonblocking TCP
data path. It is designed as a practical reference and reusable starting point
that could be extended for a future business-critical service whose
authenticated clients connect across a LAN, WAN, or the Internet.
The project combines an `epoll`-based server, bounded event-loop and worker
architectures, an OpenSSL transport layer, and a concurrent benchmark client
that can run on the same host or on a separate machine. The same application
protocol can run over mutually authenticated TLS or explicit plaintext TCP,
allowing the security, latency, throughput, CPU, and connection-management
costs of both transport modes to be measured with comparable application
workloads.

## Purpose

The project demonstrates how to:

- integrate OpenSSL below the application protocol while preserving a common
  application-data path for TLS and plaintext TCP;
- use TLS 1.3 by default and optionally measure restricted TLS 1.2 compatibility
  with explicitly configured ECDHE and AEAD cipher-suite policies;
- implement mutual TLS, certificate-chain and validity verification, server
  hostname/IP verification, client SAN authorization, optional CRL checking,
  encrypted private-key loading, and validated certificate reloads;
- disable legacy protocol versions, TLS compression, renegotiation, session
  resumption, and TLS 1.3 early data to keep the educational security model
  explicit and resistant to downgrade and replay mistakes;
- advance nonblocking TLS handshakes and OpenSSL read/write retry states within
  level-triggered `epoll` event loops without blocking an event-loop thread;
- handle many TCP connections using multiple independent event loops,
  `SO_REUSEPORT` listeners, per-loop ownership, and bounded work per event;
- provide reusable bounded executor and `eventfd` completion-queue primitives
  for future services that must offload work without blocking event loops;
- process fragmented and pipelined requests, partial TCP/TLS writes, disconnects,
  stale epoll events, and file-descriptor reuse safely;
- enforce limits and absolute deadlines for connections, TLS handshakes,
  incomplete requests, queued responses, and idle sessions;
- use RAII for sockets, epoll descriptors, OpenSSL objects, threads, mapped
  memory, and sensitive passphrase storage;
- separate reusable event-loop, protocol, completion, and transport concerns
  from the included request-to-response mapping service;
- preserve mapping-backed scatter/gather output in plaintext mode and explicit
  output-buffer lifetime across partial writes and TLS retries;
- measure request throughput, response bandwidth, handshake outcomes, connection
  failures, and concurrency behavior over TLS 1.2, TLS 1.3, and plaintext TCP;
  and
- provide sanitizer, hardened production-test, and CPU-specific performance
  builds for correctness and controlled benchmarking.

The project is intended for systems-programming and TLS education, functional
validation, architecture experiments, and controlled performance comparisons.
It demonstrates security-conscious implementation techniques but is not, by
itself, a complete Internet-facing service or a guarantee of production
security. Application authorization, rate limiting, audit integration, key and
certificate lifecycle automation, operating-system hardening, dependency
patching, monitoring, and deployment-specific threat controls remain the
operator's responsibility.

## Practical future use

It is practical to reuse the transport and event-loop architecture for another
service. A future application can implement `ProtocolFactory` and
`ProtocolConnection` to replace the included request-to-response mapping logic
while retaining the nonblocking sockets, `epoll` workers, TLS state machine,
connection limits, deadlines, graceful shutdown, and certificate reload path.
CPU-intensive or blocking business logic can use the bounded executor and
generation-checked completion queue rather than blocking an event-loop thread.

This separation makes the project a useful foundation, not a drop-in production
platform. Before carrying customer or business-critical traffic, an adopter
would still need to add and validate the capabilities required by its service,
including:

- an application protocol with versioning, structured errors, input validation,
  request identifiers, and compatibility rules;
- identity-to-permission authorization, tenant isolation, quotas, and rate
  limiting above the existing mTLS client identity check;
- production PKI integration, automated enrollment and rotation, revocation or
  OCSP policy, and secret-manager, TPM, or HSM-backed key handling;
- service supervision, structured audit and operational logs, metrics, tracing,
  health checks, alerting, and safe configuration rollout and rollback;
- deployment hardening, firewall and network policy, dependency and operating
  system patching, backup and recovery procedures, and capacity planning; and
- protocol fuzzing, sustained and failure-injection tests, external security
  review, and workload-specific latency and throughput qualification.

Those additions are feasible without replacing the core TCP/TLS event-loop
model, but their design depends on the target application's threat model,
availability objectives, data sensitivity, and regulatory requirements.

## High-level design

```text
       client machine                       server machine

 client_request_keys.txt          +-----------------------------+
          |                       | tcp_server_epoll            |
          v                       |                             |
 +----------------+  requests     | worker 1: epoll event loop  |
 | tcp_client     |-------------->| worker 2: epoll event loop  |
 | worker threads |<--------------| worker N: epoll event loop  |
 +----------------+  responses    +--------------+--------------+
                                                  |
                                                  v
                              server_request_response_mapping.bin
                                      request key -> binary payload
```

## Secure TLS and plaintext transport modes

Both executables support the same application framing over either transport:

- `--transport tls` (the default) uses mutual TLS, requires TLS 1.3 by default,
  and requires certificates from configured trust roots. `--tls-version tls12`
  forces a controlled TLS 1.2 benchmark; `tls12-or-tls13` permits compatibility
  while continuing to prefer TLS 1.3.
- `--transport tcp` preserves the educational plaintext implementation. It
  provides no confidentiality, peer authentication, or integrity protection.

There is no automatic TLS-to-plaintext downgrade. TLS startup fails closed when
credentials are absent or invalid. Run the modes on different ports when testing
them concurrently.

`secure_transport.h` and `secure_transport.cpp` form the transport abstraction
below the application framing. They own the OpenSSL contexts and sessions and
expose handshake, read, write, and shutdown operations. The request/response
code therefore operates on the same plaintext application messages in both
modes; TLS encrypts and authenticates those bytes before socket I/O.

### Enforced TLS policy

The default minimum and maximum protocol version is TLS 1.3. SSLv2, SSLv3,
TLS 1.0, and TLS 1.1 can never be enabled through the command line. Use the
same explicit policy on both peers when running a version-specific benchmark:

- `--tls-version tls13`: TLS 1.3 only and the default;
- `--tls-version tls12`: TLS 1.2 only, for controlled compatibility comparison;
- `--tls-version tls12-or-tls13`: allow both and prefer TLS 1.3; or
- `--tls-allow-tls12`: compatibility alias for `tls12-or-tls13`.

TLS 1.2-only mode remains restricted to the ECDHE+AEAD suites below. It is not
a recommendation to prefer TLS 1.2 for new deployments.

The permitted TLS 1.3 cipher suites are:

- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

TLS 1.2 compatibility permits only
`ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES256-GCM-SHA384`,
`ECDHE-ECDSA-CHACHA20-POLY1305`, `ECDHE-RSA-CHACHA20-POLY1305`,
`ECDHE-ECDSA-AES128-GCM-SHA256`, and `ECDHE-RSA-AES128-GCM-SHA256`.
Static RSA, CBC, RC4, 3DES, anonymous, and non-forward-secret suites are
excluded. Allowed key-exchange groups are X25519, P-256, and P-384.
Compression and renegotiation are disabled, and OpenSSL security level 2 is
applied.

Both sides validate the peer certificate chain against the explicitly supplied
CA bundle, including certificate validity dates and the certificate purpose.
The client additionally verifies `--tls-server-name` against the server's DNS
or IP subjectAltName; DNS partial wildcards are rejected. It never disables
hostname checking. The server requires a client certificate and, after chain
validation, requires an exact DNS or URI SAN match from the allowlist.

For a local lab, generate a private test CA and distinct server/client identities:

```bash
./generate_lab_certs.sh --output-dir certs/lab \
    --server-dns localhost --server-ip 127.0.0.1 \
    --client-name tcp-client-01 --encrypted
```

Run `./generate_lab_certs.sh --help` for all arguments, secure and insecure
examples, and warnings about unencrypted keys. Named options are recommended
because they avoid ambiguity in the legacy positional form.

The generator asks OpenSSL for separate passphrases and creates encrypted PKCS#8
CA, server, and client private keys by default. The passphrases are read directly
by OpenSSL without appearing in the command line or shell history. Choose strong,
unique passphrases and store them in a password manager. The server and client
prompt for their respective key passphrase while loading `--tls-key`; the CA
passphrase is needed when creating the CA and must be re-entered when signing
both the server and client certificates. The script labels each prompt and states
which passphrase is required. This interactive mechanism is intended for a
terminal-based lab, not unattended service startup.

At runtime the executable identifies both the key role and file. For example,
the server displays `Enter SERVER private-key passphrase for
certs/lab/server.key.pem:`, while the client displays `Enter CLIENT private-key
passphrase for certs/lab/client.key.pem:`. These prompts require the server and
client leaf-key passphrases respectively—not the CA passphrase.

For disposable automated lab tests only, append `unencrypted` as the fifth
argument:

```bash
./generate_lab_certs.sh --output-dir certs/lab-ci \
    --server-dns localhost --server-ip 127.0.0.1 \
    --client-name tcp-client-ci --unencrypted
```

That mode prints a warning and relies on restrictive file permissions. Never
place a password in a command-line argument, source file, environment variable,
or committed configuration.

For noninteractive loading of an encrypted leaf key, both executables accept
`--tls-key-passphrase-file PATH`. The file must be a regular file owned by the
effective service user, must have no group or other permission bits (mode `0600`
or stricter), must not be a symbolic link, and must contain only the passphrase
with an optional final newline. The passphrase is loaded once, retained in
process memory for TLS context reloads, and cleansed when its final owner is
destroyed. Prefer a short-lived, memory-backed credential file provisioned by a
service manager or secret manager; do not commit or permanently store it beside
the key. A wrong owner or permissive mode fails closed.

For stronger unattended production key isolation, use an HSM, TPM, or an
OpenSSL provider appropriate to the deployment. The credential-file option
protects a password at the filesystem boundary but does not give hardware-backed
non-exportability.

The generator is intentionally for education only. Enterprise deployments should
obtain the server identity from an organizational or public CA, client identities
from an organizational CA, protect private keys with the platform secret manager
or HSM, automate short-lived certificate renewal, and maintain revocation and
authorization policy. Never commit generated private keys.

TLS mode also requires an exact client SAN authorization allowlist. Each
non-comment line is `URI:<value>` or `DNS:<value>` and must exactly match a SAN
in the verified client certificate. Certificate-chain trust authenticates the
client; this allowlist authorizes it. Optional `--tls-client-crl` and
`--tls-server-crl` files enable full-chain CRL checking. Revocation is not
checked when the corresponding option is omitted. The program does not fetch
CRLs and does not implement OCSP, so operators must securely distribute and
refresh CRL files before they expire. An invalid configured CRL fails startup or
reload rather than silently disabling revocation checking.

Send `SIGHUP` to the server after atomically replacing certificate, key, CA,
CRL, or allowlist files. A complete new TLS context is validated and published
for new connections; existing connections retain their original context. A
failed reload leaves the last known-good context active. When
`--tls-key-passphrase-file` is configured, reload securely rereads that credential
file together with the key. Reload never requests an interactive passphrase: if
the replacement key is encrypted and no credential file was configured, reload
fails immediately and retains the last known-good context. This keeps the
coordinator responsive to shutdown and later reload signals under systemd,
containers, and other unattended environments.

Session tickets, session caching, TLS 1.3 PSK-only resumption, and TLS 1.3 0-RTT
are disabled. Every TCP reconnect performs a new certificate-verified mTLS
handshake and fresh ephemeral key exchange. This intentionally favors a simple
security model over abbreviated-handshake performance.

Incomplete TLS handshakes have an absolute 10-second deadline. Each server event
loop allows at most 1,024 concurrent handshakes (or its lower configured
connection limit), rate-limits repetitive TLS error logging, and reports
successful, failed, and capacity-rejected handshake totals at shutdown. These
controls reduce resource-exhaustion exposure but do not replace firewall,
load-balancer, monitoring, or application-level rate limits.

Start an mTLS server and client:

```bash
./build/production/tcp_server_epoll --listen 23457 --transport tls \
    --tls-cert certs/lab/server.cert.pem \
    --tls-key certs/lab/server.key.pem \
    --tls-client-ca certs/lab/ca.cert.pem \
    --tls-client-allowlist certs/lab/client-san-allowlist.txt

./build/production/tcp_client 127.0.0.1 23457 --transport tls \
    --tls-ca certs/lab/ca.cert.pem \
    --tls-cert certs/lab/client.cert.pem \
    --tls-key certs/lab/client.key.pem \
    --tls-server-name 127.0.0.1
```

For use across a WAN or NAT, use the reachable address in the first client
argument but pass the certificate identity in `--tls-server-name`. The server
certificate must contain that exact DNS name or IP address in its SAN. Prefer a
stable private DNS name, an organizational CA, a VPN/private network, and a
firewall rule limited to intended clients. NAT does not provide authentication
or encryption. Copy only the required CA certificates and each host's own leaf
certificate/key; never copy the CA private key to either runtime host.

Add `--tls-client-crl PATH` to the server and `--tls-server-crl PATH` to the
client when CRLs are deployed. Use `--tls-version tls12` on both commands only
for a controlled TLS 1.2 benchmark, or `tls12-or-tls13` for a measured
compatibility requirement.

For plaintext comparison, specify it explicitly on both processes:

```bash
./build/production/tcp_server_epoll --listen 23456 --transport tcp
./build/production/tcp_client 127.0.0.1 23456 --transport tcp
```

The main components are:

- `tcp_server_epoll` uses one `epoll` event loop per worker thread.
- Each server worker owns a `SO_REUSEPORT` listening socket, its active
  connection states, and its allocation-free timeout wheel. Connections use
  level-triggered notifications and remain assigned to one event loop for their
  lifetime. Bounded work per event provides fairness without risking an
  edge-triggered stall when configuration limits change.
- The server loads `server_request_response_mapping.bin` once at startup. The
  default `mmap-view` loader indexes keys and keeps response views in a
  read-only anonymous snapshot, avoiding per-payload allocations without
  retaining a vulnerable file-backed mapping.
- `tcp_client` opens one persistent connection per worker and reports success, throughput,
  response bandwidth, and categorized connection failures. It creates a fixed
  worker-thread set once, feeds it through a bounded condition-variable queue,
  and reuses those threads across all rounds. Each worker performs one complete
  framed request/response transaction at a time on that connection and sleeps
  without busy-spinning when the queue is empty. A stale connection is replaced
  automatically and the read-only request is retried once.
- `server_request_response_mapping.bin` stays on the server and contains keys
  plus binary response payloads.
- `client_request_keys.txt` contains only valid keys and can be copied to a
  test-client machine.

### Reusable event-loop boundary

The public reusable interfaces live under `include/epoll_runtime/`.
`protocol.h` decouples application behavior from socket readiness and TLS;
`server_protocol.h` remains a compatibility include. `EventLoop` receives an
injected `ProtocolFactory` and creates one
`ProtocolConnection` per accepted client. The event loop knows only how to:

- accept and own nonblocking connections;
- advance TCP or TLS reads and writes;
- enforce handshake, request-progress, response-progress, and idle deadlines;
- apply bounded per-event work and output backpressure; and
- shut down connections and worker threads safely.

The current `MappingProtocolConnection` implements newline parsing, hash-map
lookup, pipelined response state, and four-byte response framing behind that
interface. A future service can implement another `ProtocolFactory` without
putting its parser or datastore into the epoll code. Returned `OutputBatch`
slices must remain alive and unchanged until the event loop reports their bytes
consumed. Dynamically generated or asynchronously produced output can also set
`OutputBatch::lifetime`; the connection pins that owner through partial writes
and TLS retries. This preserves scatter/gather output without temporary payload
assembly while making dynamic-buffer ownership explicit.

Protocol callbacks run on the owning event-loop thread, are contained by a
per-connection exception boundary, and must not block. The optional
`BoundedExecutor` provides rejection-based overload control for expensive work.
`CompletionQueue<Result>` provides the bounded multi-producer return channel
and an `eventfd` that can be registered with the owning event loop. Its consumer
must validate the supplied `ConnectionId` before delivery. Connection
generations are also encoded into epoll user data,
so a stale event cannot target a newer connection after file-descriptor reuse.
Executor shutdown is explicit: `Drain` finishes queued jobs, while the default
`CancelPending` discards jobs that have not started and joins the active job.
An unexpected `eventfd` notification failure atomically rolls back completion
enqueue rather than leaving an accepted result without a reliable wakeup.

When OpenSSL retains decrypted input after one event's work budget, the runtime
puts the generation-tagged connection on a bounded deferred-read queue. This
prevents an `SSL_pending()` stall without allowing one busy TLS connection to
monopolize its event-loop thread.

The reusable surface is intentionally incremental. The mapping example and the
Linux `EventLoop::Impl` currently share `tcp_server_epoll.cpp`; future extraction
can move that implementation into a runtime library without changing the public
protocol, connection-ID, or executor contracts.

The deliberately small protocol accepts newline-terminated request keys. A
known key returns a four-byte big-endian payload length followed by its binary
payload. The server supports keep-alive and up to 16 pipelined responses per
connection; responses are emitted in request order.
An empty, oversized, unknown, or excessively pipelined request closes the
connection. The bundled client reuses one connection per worker across requests
and rounds. This is not HTTP; the binary length prefix is the response-framing
contract and is included in network bytes but excluded from payload statistics.

Client rounds have an intentional completion barrier: all requests in a round
finish before its consolidated statistics and optional ordered verbose results
are printed, and only then may the next `--forever` round begin. This makes
rounds independently comparable. It introduces a small between-round barrier;
a continuous interval-reporting load generator would be preferable when the
only objective is maximum uninterrupted throughput.

## Repository layout

```text
TlsEpollRequestBench/
├── include/epoll_runtime/   Public reusable event-loop/protocol interfaces
├── src/runtime/             Runtime implementation components
├── tests/                   Runtime contract tests
├── secure_transport.*       OpenSSL TLS context and session abstraction
├── tcp_server_epoll.*       Epoll server and mapping-service example
├── tcp_client.cpp           Concurrent TCP/TLS benchmark client
├── tcp_common_config.h      Shared application framing limits
├── generate_lab_certs.sh    Lab-only CA and certificate generator
├── Makefile                 Build and test targets
├── README.md                Usage, architecture, and security guidance
└── LICENSE                  Repository usage terms
```

Source files, public headers, tests, the build definition, documentation, and
the certificate generator belong in Git. The ignored `build/`, `cert/`, and
`certs/` directories are local generated material. Generated mapping files,
client request-key lists, binaries, private keys, passphrase files, logs, and
crash dumps must not be committed. A clean checkout recreates required binaries
with `make` and lab credentials with `generate_lab_certs.sh`.

## Requirements

- Linux server with a C++23-capable GCC toolchain
- Boost 1.81 or newer development headers for `boost::unordered_flat_map`
- OpenSSL 3.x development headers and `pkg-config`
- Linux or another POSIX client supported by this source
- Network access from the client to the chosen server TCP port
- `scp` for copying the key file, or an equivalent file-transfer tool

On Fedora/RHEL install `openssl-devel`, `boost-devel`, and `pkgconf-pkg-config`.
On Debian/Ubuntu install `libssl-dev`, `libboost-dev`, and `pkg-config`.

OpenSSL 3.x is a maintained general-purpose production TLS implementation. An
enterprise requiring a validated cryptographic boundary (for example FIPS
140-3) must use its platform's validated OpenSSL provider and configuration;
linking this application to an arbitrary OpenSSL build does not itself provide
that validation.

Production operations must continuously patch the dynamically linked OpenSSL
packages, restart the service after library updates, monitor vendor security
advisories, and scan deployed artifacts. No application cipher policy can
guarantee protection from future implementation vulnerabilities in libssl.

Recommended production PKI practice is an offline root, an issuing intermediate,
short-lived leaf certificates, protected private keys, automated rotation, and
CRL or equivalent revocation publication. The included generator deliberately
uses a simpler lab-only CA and must not become the production issuer.

## Build

The included `Makefile` builds the server and client together. Run one of these
targets inside the `TlsEpollRequestBench` directory:

```bash
make debug
make sanitizer
make production
make performance
make test
```

`make test` builds and runs the reusable runtime contract tests. Run it in
addition to the desired executable build; it does not start a network server.

The variants are kept in separate directories:

- `build/debug`: `-Og -g3`, frame pointers, and libstdc++ assertions for GDB.
- `build/sanitizer`: AddressSanitizer and UndefinedBehaviorSanitizer for finding
  memory and undefined-behavior bugs. Do not benchmark this build.
- `build/production`: portable `-O2` build with stack protection, fortified libc
  calls, PIE, RELRO, and immediate symbol binding. This is the default target.
- `build/performance`: `-O3 -march=native -flto` for benchmark measurements on
  the machine where it was built. A `-march=native` binary may not run on an
  older or different CPU.

Build every variant or display the available targets with:

```bash
make all
make help
```

The examples below use the production binaries. Substitute
`build/debug`, `build/sanitizer`, or `build/performance` when appropriate.

## Getting started

The following is the shortest complete local TLS workflow after creating the
GitHub repository. Replace the example URL with the repository's actual URL:

```bash
git clone https://github.com/OWNER/TlsEpollRequestBench.git
cd TlsEpollRequestBench
make production
make test
```

Generate a small server dataset and matching client request list:

```bash
./build/production/tcp_server_epoll \
    --mapping-file server_request_response_mapping.bin \
    --mapping-entries 10000 --regen-mapping \
    --export-keys 10000 --keys-output client_request_keys.txt
```

Generate encrypted lab-only mTLS credentials. OpenSSL will ask for distinct CA,
server-key, and client-key passphrases as described in the TLS section above:

```bash
./generate_lab_certs.sh --output-dir certs/lab \
    --server-dns localhost --server-ip 127.0.0.1 \
    --client-name tcp-client-01 --encrypted
```

Start the server in the first terminal:

```bash
./build/production/tcp_server_epoll --listen 23457 --transport tls \
    --mapping-file server_request_response_mapping.bin \
    --tls-cert certs/lab/server.cert.pem \
    --tls-key certs/lab/server.key.pem \
    --tls-client-ca certs/lab/ca.cert.pem \
    --tls-client-allowlist certs/lab/client-san-allowlist.txt
```

Run the client in a second terminal:

```bash
./build/production/tcp_client 127.0.0.1 23457 --transport tls \
    --keys-file client_request_keys.txt \
    --tls-ca certs/lab/ca.cert.pem \
    --tls-cert certs/lab/client.cert.pem \
    --tls-key certs/lab/client.key.pem \
    --tls-server-name 127.0.0.1
```

For a plaintext comparison using the same dataset and application framing, stop
the TLS server and run the commands in the following quick-test section with
`--transport tcp`. Plaintext mode has no confidentiality, authentication, or
integrity protection.

## Quick local test

First create a small mapping. Creation is explicit so starting the server from
the wrong directory cannot silently generate a large file:

```bash
./build/production/tcp_server_epoll \
    --mapping-file server_request_response_mapping.bin \
    --mapping-entries 10000 \
    --regen-mapping \
    --export-keys 10000 \
    --keys-output client_request_keys.txt
```

Start the server in the first terminal. `--regen-mapping` is intentionally
omitted so this run reuses the exact mapping from which the keys were exported:

```bash
./build/production/tcp_server_epoll \
    --listen 8080 --transport tcp \
    --event-loops 4 \
    --max-connections-per-loop 10000 \
    --idle-timeout-seconds 15 \
    --mapping-file server_request_response_mapping.bin \
    --mapping-loader mmap-view
```

Run a smoke test in a second terminal:

```bash
./build/production/tcp_client 127.0.0.1 8080 --transport tcp \
    --keys-file client_request_keys.txt \
    --request-count 100 \
    --max-concurrency 10
```

A healthy run reports `success=100 failed=0 connect_failed=0`. Stop the server
with `Ctrl+C`. The first termination signal drains existing connections; a
second signal forces shutdown.

## Test from a different machine

### 1. Prepare the server dataset and client keys

On the server machine, generate the mapping and key file once. For an initial
remote test, 10,000 entries is sufficient:

```bash
cd /path/to/TlsEpollRequestBench

./build/production/tcp_server_epoll \
    --mapping-file server_request_response_mapping.bin \
    --mapping-entries 10000 \
    --regen-mapping \
    --export-keys 10000 \
    --keys-output client_request_keys.txt
```

For a larger working set, increase `--mapping-entries` up to 500,000. The full
500,000-entry mapping is approximately 1.5 GB and requires additional memory,
disk space, and generation time.

### 2. Copy only the keys to the client

From the client machine, pull the file from the server:

```bash
scp USER@SERVER_IP:/path/to/TlsEpollRequestBench/client_request_keys.txt \
    /path/to/TlsEpollRequestBench/
```

Do not copy `server_request_response_mapping.bin`; it is server-only data.
Optionally run `sha256sum client_request_keys.txt` on both machines to confirm
that the transfer produced identical files.

### 3. Start exactly one server

Exporting keys and listening can be combined in one invocation. This guarantees
that the exported keys and active mapping come from the same loaded dataset:

```bash
./build/production/tcp_server_epoll \
    --listen 8080 --transport tcp \
    --event-loops 8 \
    --max-connections-per-loop 10000 \
    --idle-timeout-seconds 15 \
    --mapping-file server_request_response_mapping.bin \
    --mapping-loader mmap-view \
    --export-keys 10000 \
    --keys-output client_request_keys.txt
```

If this command exports a new key file, copy that file to the client before
testing. The server has a per-user, per-port lock that prevents another
current-version server process from silently joining the same `SO_REUSEPORT`
group. Also check for older builds that do not have this protection:

```bash
ps -ef | grep '[t]cp_server_epoll'
ss -ltnp 'sport = :8080'
```

### 4. Confirm network access

The server listens on all IPv4 interfaces. Confirm its address and port:

```bash
ip -brief address
ss -ltnp 'sport = :8080'
```

Permit the port only from the intended client IP using the host firewall and,
when applicable, the cloud security group. Prefer a private network or VPN.

### 5. Run the remote client

On the client machine:

```bash
cd /path/to/TlsEpollRequestBench

./build/production/tcp_client SERVER_IP 8080 --transport tcp \
    --keys-file client_request_keys.txt \
    --request-count 1000 \
    --max-concurrency 32
```

Replace `SERVER_IP` with an IPv4 address reachable from the client. A successful
run reports zero failures. The client exits with status `2` if any request fails,
which makes it usable in automated test scripts.

Connection failures are reported with the server IP and port. An immediate
`connection refused` normally means the host responded but nothing is listening
on that port. A timeout or unreachable message normally indicates an incorrect
IP address, missing route, firewall/security-group filtering, or an unavailable
server. The connection timeout is five seconds.

## Scalability and performance testing

Build with `-O2 -DNDEBUG`, use summary mode, and run the client from another
machine so server and client CPU usage do not compete. Do not use `--verbose`
for benchmarks because terminal output overwhelms the workload.

Run a concurrency sweep instead of testing only one value:

```bash
./build/performance/tcp_client SERVER_IP 8080 --transport tcp --request-count 100000 --max-concurrency 1
./build/performance/tcp_client SERVER_IP 8080 --transport tcp --request-count 100000 --max-concurrency 8
./build/performance/tcp_client SERVER_IP 8080 --transport tcp --request-count 100000 --max-concurrency 32
./build/performance/tcp_client SERVER_IP 8080 --transport tcp --request-count 100000 --max-concurrency 128
./build/performance/tcp_client SERVER_IP 8080 --transport tcp --request-count 100000 --max-concurrency 256
```

Record these fields for every run:

- `success`, `failed`, and `connect_failed`
- `elapsed_ms`
- `requests_per_second`
- `successful_MiB_per_second`
- server and client CPU utilization
- server resident memory and network utilization

Increase concurrency until throughput stops improving or failures become
unacceptable. For higher load, run clients from multiple machines. This client
uses a closed-loop workload: each worker starts another request after its
previous request finishes. Therefore, `--max-concurrency` is a maximum number of
simultaneous requests, not a guaranteed arrival rate.

For a meaningful protocol-version comparison, force the same version on both
peers. Merely permitting TLS 1.2 normally negotiates TLS 1.3 when it is available:

```bash
# Add to both server and client for the TLS 1.3 run:
--tls-version tls13

# Add to both server and client for the TLS 1.2 compatibility run:
--tls-version tls12
```

Keep credentials, mapping data, concurrency, request count, CPU affinity, and
machine load identical between runs. Record the negotiated protocol and cipher
along with throughput and latency results.

Before a high-concurrency test, inspect file-descriptor limits on both machines:

```bash
ulimit -n
```

Choose `--event-loops` based on measurement. The number of available CPU cores
is a reasonable starting point, but more loops are not automatically faster.
Each worker reuses one TCP connection. Connection setup and teardown are
amortized across its requests; a reconnect is performed after a stale socket or
I/O failure.

## Useful client options

- `--request-count N`: requests sent in each round
- `--max-concurrency N`: maximum worker threads and in-flight requests; the
  default is one worker per CPU reported as available to the process (or one
  worker if CPU detection is unavailable)
- `--queue-capacity N`: bounded number of requests waiting for workers; the
  default is twice the effective worker count, capped by the requests in one
  round
- `--round-delay-ms N`: interruptible delay between `--forever` rounds; useful
  for pacing sustained tests and reducing reconnect pressure
- `--forever`: repeat rounds until interrupted
- `--verbose`: print each binary response as a hex dump; debugging only
- `--keys-file PATH`: use a non-default key file

For TLS runs, each round also reports `negotiated_tls=VERSION/CIPHER`. If
reconnects negotiate different parameters, the client marks the result as mixed
so a version or cipher comparison is not accidentally reported as homogeneous.

The client creates its worker threads and per-worker connections once and joins
them at shutdown. The CPU-aware default is deliberately conservative. For
example, a two-CPU machine defaults to two workers. Higher concurrency can
improve throughput when workers spend most of their time waiting on a remote
network, but should be enabled explicitly after measuring CPU use, latency, and
failures.
The first SIGINT or SIGTERM stops submission, discards queued work, allows
active socket send or receive phase to finish within its absolute five-second
deadline, closes
each worker's persistent socket, and joins the workers. A second signal exits
immediately.

## Mapping loaders

- `ifstream`: copies all keys and payloads into owned memory.
- `mmap`: reads the file into an anonymous mapping, marks it read-only, parses
  it, and copies entries into owned containers.
- `mmap-view`: reads the file into an anonymous mapping, marks it read-only,
  and keeps validated key/payload views into that immutable snapshot.

Neither mmap mode retains a live file-backed mapping, so truncating or replacing
the source file after startup cannot cause `SIGBUS` or mutate active views.
Regenerate and re-export keys together; keys from another mapping are rejected.
The `mmap-view` server avoids an additional application payload copy when the
plaintext path passes mapping-backed slices to `sendmsg`. This is not end-to-end
zero-copy: the anonymous snapshot is populated once at startup, request framing
uses connection memory, the client receives into a vector, and TLS necessarily
encrypts plaintext through OpenSSL record buffers. For TLS responses, the
four-byte framing header and payload are copied into lazily allocated,
per-connection coalescing storage and passed to one `SSL_write_ex` call. This
avoids creating a separate TLS record for the header; the storage remains stable
across OpenSSL retry states and adds only one pointer to the inline connection
state. Once a connection sends a response, it retains approximately 4 KB of
heap capacity for reuse so later responses do not allocate in the data path.

## Security and scope

This remains a benchmarking and educational application protocol rather than a
complete Internet-facing service. TLS mode supplies confidentiality, integrity,
mutual certificate authentication, and exact client SAN authorization. It does
not provide per-request permissions, tenant isolation, request-level error
responses, application rate limiting, automated certificate enrollment,
automated revocation retrieval, OCSP, audit-log integration, or protection from
future OpenSSL implementation defects. Plaintext mode supplies none of the TLS
security properties. Restrict firewall access to designated clients and place
production deployments behind appropriate network and operational controls.

Request lookup uses process-randomized SipHash. Partial request lines must be
completed within 10 seconds, and queued responses must drain within 30 seconds;
ordinary socket activity cannot extend those absolute progress deadlines.

The client validates response size but does not verify payload contents. A
content-integrity test would require a manifest containing each key's expected
payload size and cryptographic digest.
