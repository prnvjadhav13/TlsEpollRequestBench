# TcpEpollRequestBench

TcpEpollRequestBench is a C++23/Linux project for learning, validating, and
measuring a scalable TCP request/response design. It includes an `epoll`-based
server and a concurrent load-test client that can run on the same machine or on
different machines.

## Purpose

The project demonstrates how to:

- handle many TCP connections with multiple independent `epoll` event loops;
- distribute accepted connections across server workers with `SO_REUSEPORT`;
- process fragmented requests and partial nonblocking writes safely;
- enforce connection, request-size, and idle-time limits;
- keep file descriptors and memory mappings under RAII ownership;
- separate private server response data from a small client test-key file; and
- measure request throughput, response bandwidth, and connection failures at
  different concurrency levels.

It is intended for systems-programming education, functional testing, and
controlled performance experiments. It is not, by itself, an authenticated or
encrypted Internet-facing service.

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

The main components are:

- `tcp_server_epoll` uses one `epoll` event loop per worker thread.
- Each server worker owns a `SO_REUSEPORT` listening socket, its active
  connection states, and its idle-timeout queue. Connections are nonblocking
  and remain assigned to one event loop for their lifetime.
- The server loads `server_request_response_mapping.bin` once at startup. The
  default `mmap-view` loader indexes keys and keeps response views in the mapped
  file, avoiding duplicate user-space payload storage.
- `tcp_client` opens concurrent connections and reports success, throughput,
  response bandwidth, and categorized connection failures. Each client worker
  repeatedly performs one complete request/response transaction at a time.
- `server_request_response_mapping.bin` stays on the server and contains keys
  plus binary response payloads.
- `client_request_keys.txt` contains only valid keys and can be copied to a
  test-client machine.

The deliberately small protocol supports one transaction per connection. The
client sends a newline-terminated request key. A known key returns its binary
payload, after which the server closes the connection. An empty, oversized, or
unknown request is closed without a response. Consequently, benchmark results
include TCP connection establishment and teardown costs.

## Requirements

- Linux server with a C++23-capable GCC toolchain
- Linux or another POSIX client supported by this source
- Network access from the client to the chosen server TCP port
- `scp` for copying the key file, or an equivalent file-transfer tool

## Build

The included `Makefile` builds the server and client together. Run one of these
targets inside the `tcp_program` directory:

```bash
make debug
make sanitizer
make production
make performance
```

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
make all-variants
make help
```

The examples below use the production binaries. Substitute
`build/debug`, `build/sanitizer`, or `build/performance` when appropriate.

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
    --listen 8080 \
    --event-loops 4 \
    --max-connections-per-loop 10000 \
    --idle-timeout-seconds 15 \
    --mapping-file server_request_response_mapping.bin \
    --mapping-loader mmap-view
```

Run a smoke test in a second terminal:

```bash
./build/production/tcp_client 127.0.0.1 8080 \
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
cd /path/to/tcp_program

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
scp USER@SERVER_IP:/path/to/tcp_program/client_request_keys.txt \
    /path/to/tcp_program/
```

Do not copy `server_request_response_mapping.bin`; it is server-only data.
Optionally run `sha256sum client_request_keys.txt` on both machines to confirm
that the transfer produced identical files.

### 3. Start exactly one server

Exporting keys and listening can be combined in one invocation. This guarantees
that the exported keys and active mapping come from the same loaded dataset:

```bash
./build/production/tcp_server_epoll \
    --listen 8080 \
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
cd /path/to/tcp_program

./build/production/tcp_client SERVER_IP 8080 \
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
./build/performance/tcp_client SERVER_IP 8080 --request-count 100000 --max-concurrency 1
./build/performance/tcp_client SERVER_IP 8080 --request-count 100000 --max-concurrency 8
./build/performance/tcp_client SERVER_IP 8080 --request-count 100000 --max-concurrency 32
./build/performance/tcp_client SERVER_IP 8080 --request-count 100000 --max-concurrency 128
./build/performance/tcp_client SERVER_IP 8080 --request-count 100000 --max-concurrency 256
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

Before a high-concurrency test, inspect file-descriptor limits on both machines:

```bash
ulimit -n
```

Choose `--event-loops` based on measurement. The number of available CPU cores
is a reasonable starting point, but more loops are not automatically faster.
Each request uses a new TCP connection, so results include connection setup and
teardown cost.

## Useful client options

- `--request-count N`: requests sent in each round
- `--max-concurrency N`: maximum worker threads and in-flight requests
- `--forever`: repeat rounds until interrupted
- `--verbose`: print each binary response as a hex dump; debugging only
- `--keys-file PATH`: use a non-default key file

## Mapping loaders

- `ifstream`: copies all keys and payloads into owned memory.
- `mmap`: parses with `mmap` but copies entries into owned memory.
- `mmap-view`: keeps validated views into the mapped file and has the lowest
  copying and memory overhead.

While `mmap-view` is active, never truncate or modify the mapped inode. Generate
a complete replacement file and atomically rename it, or stop the server before
regenerating. Regenerate and re-export keys together; keys from another mapping
produce zero-byte responses.

## Security and scope

This is a benchmarking/example server, not an Internet-facing application
protocol. It has no TLS, authentication, authorization, request-level error
response, or application rate limiting. Run it only on a trusted network or
behind a secured proxy/load balancer. Restrict firewall access to designated
test clients.

The client validates response size but does not verify payload contents. A
content-integrity test would require a manifest containing each key's expected
payload size and cryptographic digest.
