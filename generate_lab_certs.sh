#!/usr/bin/env bash
# Generates a short-lived private-CA mTLS identity set for local education only.
# Private keys are password-encrypted by default; use the final "unencrypted"
# argument only for disposable automation where interactive prompts are impossible.
set -euo pipefail
umask 077

usage() {
    cat <<'EOF'
Usage:
  ./generate_lab_certs.sh [options]
  ./generate_lab_certs.sh [output-dir [server-dns [server-ip [client-name [encrypted|unencrypted]]]]]

Recommended named options:
  --output-dir <path>     Destination directory (default: certs/lab)
  --server-dns <name>    DNS SAN for the server (default: localhost)
  --server-ip <address>  IP SAN for the server (default: 127.0.0.1)
  --client-name <name>   Client identity suffix (default: tcp-client-01)
  --encrypted            Password-protect all private keys (secure default)
  --unencrypted          Store private keys without passwords (insecure lab/CI only)
  -h, --help             Show this help and exit

Secure interactive lab example (default):
  ./generate_lab_certs.sh --output-dir certs/lab-secure --encrypted

Insecure disposable test example:
  ./generate_lab_certs.sh --output-dir certs/lab-ci --unencrypted

Security notes:
  --encrypted asks for separate CA, server, and client passphrases. Re-enter the
  CA passphrase when signing each leaf certificate. This is the default.

  --unencrypted avoids runtime passphrase prompts but leaves every generated
  private key, including the CA key, readable by any account that can access the
  0600 files. Never use this mode for production or retain its CA key.

The destination must not already exist; the script never overwrites credentials.
EOF
}

output_dir=certs/lab
server_dns=localhost
server_ip=127.0.0.1
client_name=tcp-client-01
key_protection=encrypted
positional_index=0

while (($# > 0)); do
    case "$1" in
    -h|--help)
        usage
        exit 0
        ;;
    --output-dir|--server-dns|--server-ip|--client-name)
        if (($# < 2)); then
            echo "Option $1 requires a value." >&2
            usage >&2
            exit 2
        fi
        option=$1
        value=$2
        case "$option" in
        --output-dir) output_dir=$value ;;
        --server-dns) server_dns=$value ;;
        --server-ip) server_ip=$value ;;
        --client-name) client_name=$value ;;
        esac
        shift 2
        ;;
    --encrypted)
        key_protection=encrypted
        shift
        ;;
    --unencrypted)
        key_protection=unencrypted
        shift
        ;;
    --*)
        echo "Unknown option: $1" >&2
        usage >&2
        exit 2
        ;;
    *)
        if ((positional_index < 4)) &&
           [[ "$1" == encrypted || "$1" == unencrypted || "$1" == unenrypted ]]; then
            echo "Encryption mode is misplaced or misspelled: $1" >&2
            echo "Use the explicit --encrypted or --unencrypted option." >&2
            exit 2
        fi
        case "$positional_index" in
        0) output_dir=$1 ;;
        1) server_dns=$1 ;;
        2) server_ip=$1 ;;
        3) client_name=$1 ;;
        4) key_protection=$1 ;;
        *)
            echo "Too many positional arguments." >&2
            usage >&2
            exit 2
            ;;
        esac
        positional_index=$((positional_index + 1))
        shift
        ;;
    esac
done

case "$key_protection" in
encrypted)
    key_output_options=()
    ;;
unencrypted)
    key_output_options=(-nodes)
    echo "WARNING: generating unencrypted private keys for lab use only." >&2
    ;;
*)
    echo "Key protection must be 'encrypted' or 'unencrypted'." >&2
    usage >&2
    exit 2
    ;;
esac

if [[ -e "$output_dir" ]]; then
    echo "Refusing to overwrite existing path: $output_dir" >&2
    exit 1
fi
mkdir -p "$output_dir"

if [[ "$key_protection" == encrypted ]]; then
    echo "[1/5] Creating the lab CA key." >&2
    echo "Choose and confirm a strong NEW CA passphrase when OpenSSL prompts." >&2
fi
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    "${key_output_options[@]}" \
    -sha256 -days 3650 -subj "/CN=TlsEpollRequestBench Lab Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$output_dir/ca.key.pem" -out "$output_dir/ca.cert.pem"

if [[ "$key_protection" == encrypted ]]; then
    echo "[2/5] Creating the server key." >&2
    echo "Choose and confirm a strong NEW SERVER passphrase when OpenSSL prompts." >&2
fi
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    "${key_output_options[@]}" -sha256 \
    -subj "/CN=$server_dns" \
    -addext "subjectAltName=DNS:$server_dns,IP:$server_ip" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "keyUsage=critical,digitalSignature" \
    -keyout "$output_dir/server.key.pem" -out "$output_dir/server.csr.pem"
if [[ "$key_protection" == encrypted ]]; then
    echo "[3/5] Signing the server certificate with the CA key." >&2
    echo "Re-enter the SAME CA passphrase from step 1 (not the server passphrase)." >&2
fi
openssl x509 -req -sha256 -days 90 -copy_extensions copy \
    -in "$output_dir/server.csr.pem" -CA "$output_dir/ca.cert.pem" \
    -CAkey "$output_dir/ca.key.pem" -CAcreateserial \
    -out "$output_dir/server.cert.pem"

if [[ "$key_protection" == encrypted ]]; then
    echo "[4/5] Creating the client key." >&2
    echo "Choose and confirm a strong NEW CLIENT passphrase when OpenSSL prompts." >&2
fi
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    "${key_output_options[@]}" -sha256 \
    -subj "/CN=$client_name" \
    -addext "subjectAltName=URI:urn:tcp-bench:client:$client_name" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "keyUsage=critical,digitalSignature" \
    -keyout "$output_dir/client.key.pem" -out "$output_dir/client.csr.pem"
if [[ "$key_protection" == encrypted ]]; then
    echo "[5/5] Signing the client certificate with the CA key." >&2
    echo "Re-enter the SAME CA passphrase from step 1 (not the client passphrase)." >&2
fi
openssl x509 -req -sha256 -days 30 -copy_extensions copy \
    -in "$output_dir/client.csr.pem" -CA "$output_dir/ca.cert.pem" \
    -CAkey "$output_dir/ca.key.pem" -CAcreateserial \
    -out "$output_dir/client.cert.pem"

rm -f "$output_dir/server.csr.pem" "$output_dir/client.csr.pem" \
      "$output_dir/ca.cert.srl"
chmod 600 "$output_dir"/*.key.pem
chmod 644 "$output_dir"/*.cert.pem
printf 'URI:urn:tcp-bench:client:%s\n' "$client_name" \
    > "$output_dir/client-san-allowlist.txt"
chmod 644 "$output_dir/client-san-allowlist.txt"

echo "Created educational mTLS certificates in $output_dir"
echo "Private-key protection: $key_protection"
echo "Do not use this generated lab CA for production."
