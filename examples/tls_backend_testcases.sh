#!/bin/bash

#
# Run local TLS backend smoke tests against coap-server and coap-client.
#
# The current scope covers common TLS backend:
# - PSK handshake success
# - IPv6 PSK handshake success
# - PSK client identity-hint callback
# - PSK server identity callback
# - wrong PSK negative path
# - Client first-flight loss
# - Server HelloVerifyRequest loss
# - Server ServerHello flight loss
# - Client flight loss timeout
# - Server flight loss timeout
# - PSK SNI key selection
# - TLS-over-TCP PSK handshake success
# - TLS-over-TCP peer close handling
# - TLS-over-TCP PKI handshake success
# - PKI handshake success
# - PKI intermediate CA chain loading
# - PKI certificate chain depth limit success
# - PKI certificate chain depth exceeded negative path
# - PKI self-signed leaf allowed
# - PKI self-signed with common CA required negative
# - PKI non-self-signed with override open negative
# - PKI server PEM buffer loading
# - PKI mutual authentication success
# - PKI root CA file mutual authentication
# - PKI root CA directory mutual authentication
# - PKI invalid root CA file negative path
# - PKI invalid root CA directory negative path
# - concurrent PSK and PKI server configuration
# - PKI missing client certificate negative path
# - PKI SAN preferred over CN
# - PKI second SAN preferred over CN
# - PKI CN fallback without SAN
# - PKI bad returned CN or SAN
# - PKI Wildcard Certificate
# - PKI wrong Wildcard Certificate
# - PKI SNI certificate selection
# - wrong PKI CA negative path
#

INDIR=$(dirname "$0")

CLIENT=$INDIR/coap-client
SERVER=$INDIR/coap-server
TARGET_IP=127.0.0.1
SNI_HOST=localhost
BASE_PORT=5689
PSK_KEY=secret
BAD_PSK_KEY=wrong
SNI_PSK_KEY=snikey
PSK_IDENTITY=user
PSK_HINT=hint
SNI_PSK_HINT=snihint
CLIENT_TIMEOUT=12
TLS_LIBRARY_DIR=
PARTIAL_LOGS=no
FULL_LOGS=no
KEEP_LOGS=no
DTLS_LOGS=
INVOCATION_OPTS=no

NO_PASS=0
NO_FAIL=0
NO_SKIP=0
SERVER_PID=
LOGDIR=
SANITIZER_PATTERN="ERROR: AddressSanitizer|ERROR: LeakSanitizer|SUMMARY: AddressSanitizer|SUMMARY: LeakSanitizer|LeakSanitizer: detected memory leaks|runtime error:"

usage () {
  echo "Usage: $(basename "$0") [-c client] [-s server] [-h host] [-n sni-host] [-p base-port]"
  echo "                  [-L tls-library-dir] [-k psk-key] [-u identity]"
  echo "                  [-H hint] [-B seconds] [-D] [-P] [-F] [-K] [-I]"
  echo "  where -D - Include DTLS logging"
  echo "        -F - Full logs, when fail reporting"
  echo "        -K - Keep logs after a run"
  echo "        -P - partial logs, when fail reporting (recommended)"
  echo "        -I - Add invocation options to logs"
}

while getopts "c:s:h:n:p:L:k:u:H:IB:DPFK" OPTION; do
  case $OPTION in
    c)
      CLIENT="$OPTARG"
      ;;
    s)
      SERVER="$OPTARG"
      ;;
    h)
      TARGET_IP="$OPTARG"
      ;;
    n)
      SNI_HOST="$OPTARG"
      ;;
    p)
      BASE_PORT="$OPTARG"
      ;;
    L)
      TLS_LIBRARY_DIR="$OPTARG"
      ;;
    k)
      PSK_KEY="$OPTARG"
      ;;
    u)
      PSK_IDENTITY="$OPTARG"
      ;;
    H)
      PSK_HINT="$OPTARG"
      ;;
    D)
      DTLS_LOGS=-V7
      ;;
    B)
      CLIENT_TIMEOUT="$OPTARG"
      ;;
    P)
      PARTIAL_LOGS=yes
      ;;
    F)
      FULL_LOGS=yes
      ;;
    K)
      KEEP_LOGS=yes
      ;;
    I)
      INVOCATION_OPTS=yes
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [ ! -x "$CLIENT" ]; then
  echo "Client executable not found or not executable: $CLIENT"
  exit 1
fi

if [ ! -x "$SERVER" ]; then
  echo "Server executable not found or not executable: $SERVER"
  exit 1
fi

case "$BASE_PORT" in
  *[!0-9]*|"")
    echo "Invalid base port: $BASE_PORT"
    exit 1
    ;;
esac

format_uri_host () {
  case "$1" in
    *:*) printf '[%s]' "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}

SECURE_PORT=$((BASE_PORT + 1))
TARGET_URI_HOST=$(format_uri_host "$TARGET_IP")
SNI_URI_HOST=$(format_uri_host "$SNI_HOST")
TARGET_URI=coaps://$TARGET_URI_HOST:$SECURE_PORT/.well-known/core
SNI_URI=coaps://$SNI_URI_HOST:$SECURE_PORT/.well-known/core
TLS_URI=coaps+tcp://$TARGET_URI_HOST:$SECURE_PORT/.well-known/core
PKI_URI=coaps://$SNI_URI_HOST:$SECURE_PORT/.well-known/core
TLS_PKI_URI=coaps+tcp://$SNI_URI_HOST:$SECURE_PORT/.well-known/core
WILDCARD_URI=coaps://server.example:$SECURE_PORT/.well-known/core

if command -v mktemp >/dev/null 2>&1; then
  LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}"/libcoap-tls-backend.XXXXXX)
else
  LOGDIR=${TMPDIR:-/tmp}/libcoap-tls-backend.$$
  mkdir -p "$LOGDIR"
fi

ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:exitcode=66}
LSAN_OPTIONS=${LSAN_OPTIONS:-exitcode=66}
export ASAN_OPTIONS LSAN_OPTIONS

run_with_tls_env () {
  if [ "$INVOCATION_OPTS" = "yes" ] ; then
    echo $@
  fi
  if [ -n "$TLS_LIBRARY_DIR" ]; then
    LD_LIBRARY_PATH="$TLS_LIBRARY_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    DYLD_LIBRARY_PATH="$TLS_LIBRARY_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
      "$@"
  else
    "$@"
  fi
}

start_with_tls_env () {
  if [ "$INVOCATION_OPTS" = "yes" ] ; then
    echo $@
  fi
  if [ -n "$TLS_LIBRARY_DIR" ]; then
    export LD_LIBRARY_PATH="$TLS_LIBRARY_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export DYLD_LIBRARY_PATH="$TLS_LIBRARY_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
  fi
  exec "$@"
}

cleanup () {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" >/dev/null 2>&1
    wait "$SERVER_PID" >/dev/null 2>&1
    SERVER_PID=
  fi

  if [ "$KEEP_LOGS" = yes ]; then
    echo "Logs kept in $LOGDIR"
  else
    rm -rf "$LOGDIR"
  fi
}

trap cleanup EXIT INT TERM

show_case_logs () {
  case_name=$1
  client_log=$LOGDIR/$case_name.client
  server_log=$LOGDIR/$case_name.server

  if [ "$FULL_LOGS" = yes ]; then
    echo "--- $case_name client log ---"
    cat "$client_log"
    echo "--- $case_name server log ---"
    cat "$server_log"
  elif [ "$PARTIAL_LOGS" = yes ]; then
    echo "--- $case_name client log ---"
    [ -f "$client_log" ] &&
      grep -E "COAP_EVENT|2\\.05|No response|cannot send|DTLS retransmit|Packet [0-9]+ dropped|CN '|Identity Hint|error|alert" "$client_log" || true
    echo "--- $case_name server log ---"
    [ -f "$server_log" ] &&
      grep -E "COAP_EVENT|handler|Packet [0-9]+ dropped|DTLS retransmit|SNI '|Identity '|Switching to using|error|alert" "$server_log" || true
  fi
}

pass_case () {
  echo "Pass"
  NO_PASS=$((NO_PASS + 1))
}

skip_case () {
  echo "Skip ($1)"
  NO_SKIP=$((NO_SKIP + 1))
}

fail_case () {
  case_name=$1
  reason=$2

  echo "Fail"
  echo "  $reason"
  show_case_logs "$case_name"
  NO_FAIL=$((NO_FAIL + 1))
}

start_server () {
  case_name=$1
  loss=$2
  sni_file=$3
  proto=$4
  id_file=$5
  server_log=$LOGDIR/$case_name.server
  server_args="-A $TARGET_IP -p $BASE_PORT -k $PSK_KEY -h $PSK_HINT -v 8 $DTLS_LOGS"

  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" >/dev/null 2>&1
    wait "$SERVER_PID" >/dev/null 2>&1
    SERVER_PID=
  fi

  if [ -n "$loss" ]; then
    server_args="$server_args -l $loss"
  fi
  if [ -n "$sni_file" ]; then
    server_args="$server_args -s $sni_file"
  fi
  if [ -n "$id_file" ]; then
    server_args="$server_args -i $id_file"
  fi
  if [ -n "$proto" ]; then
    server_args="$server_args -U $proto"
  fi

  start_with_tls_env "$SERVER" $server_args > "$server_log" 2>&1 &
  SERVER_PID=$!

  for _i in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      return 1
    fi
    if [ -f "$server_log" ] &&
       grep -Eq "created (DTLS|TLS)[[:space:]]+endpoint" "$server_log"; then
      return 0
    fi
    sleep 1
  done

  return 1
}

run_client () {
  case_name=$1
  key=$2
  loss=$3
  timeout_secs=$4
  uri=${5:-$TARGET_URI}
  hint_file=$6
  client_log=$LOGDIR/$case_name.client
  client_args="-m get -k $key -u $PSK_IDENTITY -v 8 $DTLS_LOGS -B $timeout_secs"

  if [ -n "$loss" ]; then
    client_args="$client_args -l $loss"
  fi
  if [ -n "$hint_file" ]; then
    client_args="$client_args -h $hint_file"
  fi

  run_with_tls_env "$CLIENT" $client_args "$uri" > "$client_log" 2>&1
  return 0
}

generate_pki_files () {
  case_name=$1
  pki_dir=$LOGDIR/pki
  ca_conf=$pki_dir/ca.cnf
  server_conf=$pki_dir/server.cnf
  alt_server_conf=$pki_dir/alt_server.cnf
  san_server_conf=$pki_dir/san_server.cnf
  second_san_server_conf=$pki_dir/second_san_server.cnf
  wildcard_server_conf=$pki_dir/wildcard_server.cnf
  wildcard_bad_conf=$pki_dir/wildcard_bad.cnf
  cn_server_conf=$pki_dir/cn_server.cnf
  sni_server_conf=$pki_dir/sni_server.cnf
  client_conf=$pki_dir/client.cnf
  inter_conf=$pki_dir/inter.cnf
  deep_inter_conf=$pki_dir/deep_inter.cnf

  mkdir -p "$pki_dir"
  if [ -f "$pki_dir/server.pem" ] &&
     [ -f "$pki_dir/self_server.pem" ] &&
     [ -f "$pki_dir/alt_server.pem" ] &&
     [ -f "$pki_dir/san_server.pem" ] &&
     [ -f "$pki_dir/san_server.key" ] &&
     [ -f "$pki_dir/second_san_server.pem" ] &&
     [ -f "$pki_dir/second_san_server.key" ] &&
     [ -f "$pki_dir/wildcard_server.pem" ] &&
     [ -f "$pki_dir/wildcard_server.key" ] &&
     [ -f "$pki_dir/wildcard_bad.pem" ] &&
     [ -f "$pki_dir/wildcard_bad.key" ] &&
     [ -f "$pki_dir/cn_server.pem" ] &&
     [ -f "$pki_dir/cn_server.key" ] &&
     [ -f "$pki_dir/sni_combined.pem" ] &&
     [ -f "$pki_dir/chain_server.pem" ] &&
     [ -f "$pki_dir/chain_depth_ok_server.pem" ] &&
     [ -f "$pki_dir/chain_depth_ok_server.key" ] &&
     [ -f "$pki_dir/chain_depth_bad_server.pem" ] &&
     [ -f "$pki_dir/chain_depth_bad_server.key" ] &&
     [ -f "$pki_dir/client.pem" ]; then
    return 0
  fi

  cat > "$ca_conf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = libcoap-test-ca

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

  cat > "$server_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = $SNI_HOST

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SNI_HOST
EOF

  cat > "$alt_server_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = default.invalid

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = default.invalid
EOF

  cat > "$san_server_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = default.invalid

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SNI_HOST
EOF

  cat > "$second_san_server_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = default.invalid

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = default.invalid
DNS.2 = $SNI_HOST
EOF

  cat > "$wildcard_server_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = *.example

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF

  cat > "$wildcard_bad_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = *.bad

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF

  cat > "$cn_server_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = $SNI_HOST

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF

  cat > "$sni_server_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = $SNI_HOST

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SNI_HOST
EOF

  cat > "$client_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = libcoap-test-client

[v3_req]
basicConstraints = CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF

  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
    -keyout "$pki_dir/ca.key" -out "$pki_dir/ca.pem" \
    -config "$ca_conf" > "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
    -keyout "$pki_dir/bad_ca.key" -out "$pki_dir/bad_ca.pem" \
    -config "$ca_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/server.key" -out "$pki_dir/server.csr" \
    -config "$server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/server.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/server.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
    -keyout "$pki_dir/self_server.key" -out "$pki_dir/self_server.pem" \
    -config "$server_conf" -extensions v3_req \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/alt_server.key" -out "$pki_dir/alt_server.csr" \
    -config "$alt_server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/alt_server.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/alt_server.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$alt_server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/san_server.key" -out "$pki_dir/san_server.csr" \
    -config "$san_server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/san_server.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/san_server.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$san_server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/second_san_server.key" -out "$pki_dir/second_san_server.csr" \
    -config "$second_san_server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/second_san_server.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/second_san_server.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$second_san_server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/wildcard_server.key" -out "$pki_dir/wildcard_server.csr" \
    -config "$wildcard_server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/wildcard_server.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/wildcard_server.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$wildcard_server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/wildcard_bad.key" -out "$pki_dir/wildcard_bad.csr" \
    -config "$wildcard_bad_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/wildcard_bad.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/wildcard_bad.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$wildcard_bad_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/cn_server.key" -out "$pki_dir/cn_server.csr" \
    -config "$cn_server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/cn_server.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/cn_server.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$cn_server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/sni_server.key" -out "$pki_dir/sni_server.csr" \
    -config "$sni_server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/sni_server.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/sni_server.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$sni_server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/client.key" -out "$pki_dir/client.csr" \
    -config "$client_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/client.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/client.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$client_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  cat "$pki_dir/sni_server.pem" "$pki_dir/sni_server.key" \
    > "$pki_dir/sni_combined.pem" || return 1

  cat > "$inter_conf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_intermediate
prompt = no

[dn]
CN = libcoap-test-intermediate

[v3_intermediate]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/inter.key" -out "$pki_dir/inter.csr" \
    -config "$inter_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/inter.csr" \
    -CA "$pki_dir/ca.pem" -CAkey "$pki_dir/ca.key" -CAcreateserial \
    -out "$pki_dir/inter.pem" -days 1 -sha256 \
    -extensions v3_intermediate -extfile "$inter_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/chain_server.key" -out "$pki_dir/chain_server.csr" \
    -config "$server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/chain_server.csr" \
    -CA "$pki_dir/inter.pem" -CAkey "$pki_dir/inter.key" -CAcreateserial \
    -out "$pki_dir/chain_leaf.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  cat "$pki_dir/chain_leaf.pem" "$pki_dir/inter.pem" \
    > "$pki_dir/chain_server.pem" || return 1

  cat > "$deep_inter_conf" <<EOF
[v3_intermediate]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

  depth_issuer_cert=$pki_dir/ca.pem
  depth_issuer_key=$pki_dir/ca.key
  for depth_i in 1 2 3 4; do
    depth_name=chain_depth_i$depth_i
    openssl req -new -newkey rsa:2048 -nodes -sha256 \
      -keyout "$pki_dir/$depth_name.key" -out "$pki_dir/$depth_name.csr" \
      -subj "/CN=libcoap-test-$depth_name" \
      >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
    openssl x509 -req -in "$pki_dir/$depth_name.csr" \
      -CA "$depth_issuer_cert" -CAkey "$depth_issuer_key" -CAcreateserial \
      -out "$pki_dir/$depth_name.pem" -days 1 -sha256 \
      -extensions v3_intermediate -extfile "$deep_inter_conf" \
      >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
    depth_issuer_cert=$pki_dir/$depth_name.pem
    depth_issuer_key=$pki_dir/$depth_name.key
  done

  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/chain_depth_ok_server.key" \
    -out "$pki_dir/chain_depth_ok_server.csr" \
    -config "$server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/chain_depth_ok_server.csr" \
    -CA "$pki_dir/chain_depth_i3.pem" \
    -CAkey "$pki_dir/chain_depth_i3.key" -CAcreateserial \
    -out "$pki_dir/chain_depth_ok_leaf.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  cat "$pki_dir/chain_depth_ok_leaf.pem" \
      "$pki_dir/chain_depth_i3.pem" \
      "$pki_dir/chain_depth_i2.pem" \
      "$pki_dir/chain_depth_i1.pem" \
    > "$pki_dir/chain_depth_ok_server.pem" || return 1

  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$pki_dir/chain_depth_bad_server.key" \
    -out "$pki_dir/chain_depth_bad_server.csr" \
    -config "$server_conf" >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  openssl x509 -req -in "$pki_dir/chain_depth_bad_server.csr" \
    -CA "$pki_dir/chain_depth_i4.pem" \
    -CAkey "$pki_dir/chain_depth_i4.key" -CAcreateserial \
    -out "$pki_dir/chain_depth_bad_leaf.pem" -days 1 -sha256 \
    -extensions v3_req -extfile "$server_conf" \
    >> "$LOGDIR/$case_name.openssl" 2>&1 || return 1
  cat "$pki_dir/chain_depth_bad_leaf.pem" \
      "$pki_dir/chain_depth_i4.pem" \
      "$pki_dir/chain_depth_i3.pem" \
      "$pki_dir/chain_depth_i2.pem" \
      "$pki_dir/chain_depth_i1.pem" \
    > "$pki_dir/chain_depth_bad_server.pem" || return 1
  return 0
}

prepare_ca_hash_dir () {
  case_name=$1
  pki_dir=$LOGDIR/pki
  ca_dir=$pki_dir/ca_dir
  ca_hash=

  mkdir -p "$ca_dir" || return 1
  ca_hash=$(openssl x509 -in "$pki_dir/ca.pem" -subject_hash -noout \
    2>> "$LOGDIR/$case_name.openssl") || return 1
  if [ -z "$ca_hash" ]; then
    return 1
  fi
  cp "$pki_dir/ca.pem" "$ca_dir/$ca_hash.0"
}

start_pki_server () {
  case_name=$1
  cert_file=${2:-}
  key_file=${3:-}
  sni_file=${4:-}
  verify_client=${5:-no}
  root_ca_file=${6:-}
  pem_buf=${7:-no}
  with_psk=${8:-no}
  proto=${9:-}
  server_log=$LOGDIR/$case_name.server
  pki_dir=$LOGDIR/pki

  if [ -z "$cert_file" ]; then
    cert_file=$pki_dir/server.pem
  fi
  if [ -z "$key_file" ]; then
    key_file=$pki_dir/server.key
  fi

  server_args="-A $TARGET_IP -p $BASE_PORT -v 8 $DTLS_LOGS -c $cert_file -j $key_file"
  if [ -n "$root_ca_file" ]; then
    server_args="$server_args -R $root_ca_file"
  else
    server_args="$server_args -C $pki_dir/ca.pem"
  fi
  if [ "$pem_buf" = yes ]; then
    server_args="$server_args -m"
  fi
  if [ "$with_psk" = yes ]; then
    server_args="$server_args -k $PSK_KEY -h $PSK_HINT"
  fi
  if [ -n "$proto" ]; then
    server_args="$server_args -U $proto"
  fi

  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" >/dev/null 2>&1
    wait "$SERVER_PID" >/dev/null 2>&1
    SERVER_PID=
  fi

  if [ -n "$sni_file" ]; then
    server_args="$server_args -S $sni_file"
  fi
  if [ "$verify_client" != yes ]; then
    server_args="$server_args -n"
  fi

  start_with_tls_env "$SERVER" $server_args > "$server_log" 2>&1 &
  SERVER_PID=$!

  for _i in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      return 1
    fi
    if [ -f "$server_log" ] &&
       grep -Eq "created (DTLS|TLS)[[:space:]]+endpoint" "$server_log"; then
      return 0
    fi
    sleep 1
  done

  return 1
}

run_pki_client () {
  case_name=$1
  ca_file=$2
  timeout_secs=$3
  client_cert=${4:-no}
  root_ca_file=${5:-}
  uri=${6:-$PKI_URI}
  client_log=$LOGDIR/$case_name.client
  pki_dir=$LOGDIR/pki
  client_args="-m get -v 8 $DTLS_LOGS -B $timeout_secs"

  if [ -n "$root_ca_file" ]; then
    client_args="$client_args -R $root_ca_file"
  elif  [ -n "$ca_file" ]; then
    client_args="$client_args -C $ca_file"
  fi

  if [ "$client_cert" = yes ]; then
    client_args="$client_args -c $pki_dir/client.pem -j $pki_dir/client.key"
  fi

  run_with_tls_env "$CLIENT" $client_args "$uri" > "$client_log" 2>&1
  return 0
}

assert_contains () {
  file=$1
  pattern=$2

  [ -f "$file" ] || return 1
  grep -qE "$pattern" "$file"
}

assert_not_contains () {
  file=$1
  pattern=$2

  [ -f "$file" ] || return 1
  ! grep -qE "$pattern" "$file"
}

assert_either_contains () {
  first_file=$1
  second_file=$2
  pattern=$3

  assert_contains "$first_file" "$pattern" ||
    assert_contains "$second_file" "$pattern"
}

have_ipv6_loopback () {
  if command -v ip >/dev/null 2>&1; then
    ip -6 addr show dev lo 2>/dev/null | grep -q '::1/128' && return 0
  fi
  if command -v ifconfig >/dev/null 2>&1; then
    ifconfig lo0 2>/dev/null | grep -q 'inet6 ::1' && return 0
    ifconfig lo 2>/dev/null | grep -q 'inet6 ::1' && return 0
  fi
  [ -r /proc/net/if_inet6 ] &&
    grep -qi '^00000000000000000000000000000001' /proc/net/if_inet6
}

check_sanitizer_logs () {
  if grep -R -E "$SANITIZER_PATTERN" "$LOGDIR" >/dev/null 2>&1; then
    echo "Sanitizer issue detected"
    grep -R -E "$SANITIZER_PATTERN" "$LOGDIR" 2>/dev/null | head -40
    return 1
  fi
  return 0
}

run_psk_success () {
  case_name=psk_success
  echo -n "PSK success - "

  if ! start_server "$case_name" ""; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "DTLS: netif: recv[[:space:]]+[0-9]+ bytes" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "DTLS PSK GET did not complete"
  fi
}

run_psk_ipv6_success () {
  case_name=psk_ipv6_success
  saved_target_ip=$TARGET_IP
  ipv6_uri=coaps://[::1]:$SECURE_PORT/.well-known/core

  echo -n "IPv6 PSK success - "

  if ! have_ipv6_loopback; then
    skip_case "::1 is not configured"
    return
  fi

  TARGET_IP=::1
  if ! start_server "$case_name" ""; then
    TARGET_IP=$saved_target_ip
    skip_case "::1 DTLS bind is not available"
    return
  fi
  TARGET_IP=$saved_target_ip

  run_client "$case_name" "$PSK_KEY" "" "$CLIENT_TIMEOUT" "$ipv6_uri"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "IPv6 DTLS PSK GET did not complete"
  fi
}

run_psk_identity_hint_callback () {
  case_name=psk_identity_hint_callback
  echo -n "PSK client identity-hint callback - "
  hint_file=$LOGDIR/$case_name.hints

  printf '%s,%s,%s\n' "$PSK_HINT" "$PSK_IDENTITY" "$PSK_KEY" > "$hint_file"

  if ! start_server "$case_name" ""; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "" "$CLIENT_TIMEOUT" "$TARGET_URI" \
    "$hint_file"

  if assert_contains "$LOGDIR/$case_name.client" "does not support Identity Hint" ||
     assert_contains "$LOGDIR/$case_name.server" "does not support Identity Hint" ; then
    skip_case "Identity Hint not supported"
  elif assert_contains "$LOGDIR/$case_name.client" "Identity Hint '$PSK_HINT' provided" &&
     assert_contains "$LOGDIR/$case_name.client" "Switching to using '$PSK_IDENTITY' identity \\+ '$PSK_KEY' key" &&
     assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "client identity-hint callback did not select PSK"
  fi
}

run_psk_identity_callback () {
  case_name=psk_identity_callback
  echo -n "PSK server identity callback - "
  id_file=$LOGDIR/$case_name.ids

  printf ',%s,%s\n' "$PSK_IDENTITY" "$PSK_KEY" > "$id_file"

  if ! start_server "$case_name" "" "" "" "$id_file"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.server" "Identity '$PSK_IDENTITY' requested, current hint ''" &&
     assert_contains "$LOGDIR/$case_name.server" "Switching to using '$PSK_KEY' key" &&
     assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "server identity callback did not select PSK"
  fi
}

run_wrong_psk () {
  case_name=wrong_psk
  echo -n "Wrong PSK negative - "

  if ! start_server "$case_name" ""; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$BAD_PSK_KEY" "" 3

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu"; then
    pass_case
  else
    fail_case "$case_name" "wrong PSK reached an unexpected connected/application path"
  fi
}

run_client_first_flight_loss () {
  case_name=client_first_flight_loss
  echo -n "Client first-flight loss - "

  if ! start_server "$case_name" ""; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "1" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "Following packet no 1 dropped" &&
     assert_contains "$LOGDIR/$case_name.client" "DTLS retransmit timeout" &&
     assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05"; then
    pass_case
  else
    fail_case "$case_name" "client first-flight loss did not recover"
  fi
}

run_server_hello_verify_loss () {
  case_name=server_hello_verify_loss
  echo -n "Server HelloVerifyRequest loss - "

  if ! start_server "$case_name" "1"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.server" "Following packet no 1 dropped" &&
     assert_contains "$LOGDIR/$case_name.client" "DTLS: netif: recv[[:space:]]+[0-9]+ bytes" &&
     assert_either_contains "$LOGDIR/$case_name.client" \
       "$LOGDIR/$case_name.server" "DTLS retransmit timeout" &&
     assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05"; then
    pass_case
  else
    fail_case "$case_name" "server HelloVerifyRequest loss did not recover"
  fi
}

run_server_flight_loss () {
  case_name=server_flight_loss
  echo -n "Server handshake flight loss - "

  if ! start_server "$case_name" "2"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.server" "Following packet no 2 dropped" &&
     assert_either_contains "$LOGDIR/$case_name.client" \
       "$LOGDIR/$case_name.server" "DTLS retransmit timeout" &&
     assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05"; then
    pass_case
  else
    fail_case "$case_name" "server handshake flight loss did not recover"
  fi
}

run_client_flight_loss_timeout () {
  case_name=client_flight_loss_timeout
  echo -n "Client flight loss timeout - "

  if ! start_server "$case_name" ""; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "100%" 3

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|DTLS retransmit timeout"; then
    pass_case
  else
    fail_case "$case_name" "client flight loss reached an unexpected connected/application path"
  fi
}

run_server_flight_loss_timeout () {
  case_name=server_flight_loss_timeout
  echo -n "Server flight loss timeout - "

  if ! start_server "$case_name" "100%"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "" 3

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|DTLS retransmit timeout"; then
    pass_case
  else
    fail_case "$case_name" "server flight loss reached an unexpected connected/application path"
  fi
}

run_psk_sni () {
  case_name=psk_sni
  echo -n "PSK SNI key selection - "
  sni_file=$LOGDIR/$case_name.sni

  printf '%s,%s,%s\n' "$SNI_HOST" "$SNI_PSK_HINT" "$SNI_PSK_KEY" > "$sni_file"

  if ! start_server "$case_name" "" "$sni_file"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$SNI_PSK_KEY" "" "$CLIENT_TIMEOUT" "$SNI_URI"

  if assert_contains "$LOGDIR/$case_name.server" "SNI '$SNI_HOST' requested" &&
     assert_contains "$LOGDIR/$case_name.server" "Switching to using '$SNI_PSK_HINT' hint" &&
     assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05"; then
    pass_case
  else
    fail_case "$case_name" "SNI PSK selection did not complete"
  fi
}

run_tls_psk_success () {
  case_name=tls_psk_success
  echo -n "TLS-over-TCP PSK success - "

  if ! start_server "$case_name" "" "" "coaps+tcp"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_client "$case_name" "$PSK_KEY" "" "$CLIENT_TIMEOUT" "$TLS_URI"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "TLS-over-TCP PSK GET did not complete"
  fi
}

run_tls_psk_peer_close () {
  case_name=tls_psk_peer_close
  client_log=$LOGDIR/$case_name.client
  closed_server=0

  echo -n "TLS-over-TCP peer close - "

  if ! start_server "$case_name" "" "" "coaps+tcp"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_with_tls_env "$CLIENT" -m get -G 3 -k "$PSK_KEY" -u "$PSK_IDENTITY" \
    -v 8 $DTLS_LOGS -B 6 "$TLS_URI" > "$client_log" 2>&1 &
  client_pid=$!

  for _i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if assert_contains "$client_log" "2\\.05"; then
      kill "$SERVER_PID" >/dev/null 2>&1
      wait "$SERVER_PID" >/dev/null 2>&1
      SERVER_PID=
      closed_server=1
      break
    fi
    if ! kill -0 "$client_pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done

  wait "$client_pid" >/dev/null 2>&1

  if [ "$closed_server" -eq 1 ] &&
     assert_contains "$client_log" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$client_log" "2\\.05" &&
     assert_contains "$client_log" "COAP_EVENT_DTLS_(CLOSED|ERROR)" &&
     assert_contains "$client_log" "cannot send CoAP pdu" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "TLS-over-TCP peer close did not report a (D)TLS close/error event"
  fi
}

run_tls_pki_success () {
  case_name=tls_pki_success
  echo -n "TLS-over-TCP PKI success - "

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "" "" "" no "" no no "coaps+tcp"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$LOGDIR/pki/ca.pem" "$CLIENT_TIMEOUT" no "" \
    "$TLS_PKI_URI"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "TLS-over-TCP PKI GET did not complete"
  fi
}

run_pki_success () {
  case_name=pki_success
  echo -n "PKI success - "

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$LOGDIR/pki/ca.pem" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI GET did not complete"
  fi
}

# Server sends leaf+intermediate while the client trusts only the root CA.
run_pki_intermediate_chain () {
  case_name=pki_intermediate_chain
  echo -n "PKI intermediate CA chain (leaf+intermediate sent, client trusts root only) - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/chain_server.pem" \
       "$pki_dir/chain_server.key" "" no "$pki_dir/ca.pem"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" "$CLIENT_TIMEOUT" no "$pki_dir/ca.pem"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI intermediate-chain GET did not complete (intermediate CA not sent?)"
  fi
}

# Boundary case: cert_chain_verify_depth=2 allows three intermediate CAs.
run_pki_chain_depth_limit () {
  case_name=pki_chain_depth_limit
  echo -n "PKI certificate chain depth limit (leaf+3 intermediates+root) - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/chain_depth_ok_server.pem" \
       "$pki_dir/chain_depth_ok_server.key" "" no "$pki_dir/ca.pem"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" "$CLIENT_TIMEOUT" no "$pki_dir/ca.pem"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI chain at configured depth limit did not complete"
  fi
}

# Negative boundary: four intermediate CAs exceed the default chain depth.
run_pki_chain_depth_too_long () {
  case_name=pki_chain_depth_too_long
  echo -n "PKI certificate chain depth exceeded (leaf+4 intermediates+root) - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/chain_depth_bad_server.pem" \
       "$pki_dir/chain_depth_bad_server.key" "" no "$pki_dir/ca.pem"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" "$CLIENT_TIMEOUT" no "$pki_dir/ca.pem"

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_either_contains "$LOGDIR/$case_name.client" "$LOGDIR/$case_name.server" \
       "The certificate's verify depth is too long|certificate chain too long|constraint limits|unknown_ca|0x400000f|alert|No response received"; then
    pass_case
  else
    fail_case "$case_name" "PKI chain beyond configured depth limit was accepted"
  fi
}

run_pki_self_signed_leaf () {
  case_name=pki_self_signed_leaf
  echo -n "PKI self-signed leaf allowed - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/self_server.pem" \
      "$pki_dir/self_server.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "self-signed leaf PKI GET did not complete"
  fi
}

run_pki_self_signed_common_ca () {
  case_name=pki_self_signed_common_ca
  echo -n "PKI self-signed with common CA required negative - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/self_server.pem" \
      "$pki_dir/self_server.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/bad_ca.pem" "$CLIENT_TIMEOUT"

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|COAP_EVENT_DTLS_ERROR"; then
    pass_case
  else
    fail_case "$case_name" "self-signed leaf accepted while common CA was required"
  fi
}

run_pki_non_self_signed_override () {
  case_name=pki_non_self_signed_override
  echo -n "PKI non-self-signed with override open negative - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" "$CLIENT_TIMEOUT"

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|COAP_EVENT_DTLS_ERROR"; then
    pass_case
  else
    fail_case "$case_name" "non-self-signed cert accepted via self-signed override"
  fi
}

run_pki_server_pem_buf () {
  case_name=pki_server_pem_buf
  echo -n "PKI server PEM buffer loading - "

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "" "" "" no "" yes; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$LOGDIR/pki/ca.pem" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI PEM buffer server did not complete"
  fi
}

run_pki_mutual_auth () {
  case_name=pki_mutual_auth
  echo -n "PKI mutual authentication - "

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "" "" "" yes; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$LOGDIR/pki/ca.pem" "$CLIENT_TIMEOUT" yes

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "CN 'libcoap-test-client' presented by client"; then
    pass_case
  else
    fail_case "$case_name" "PKI mutual authentication did not complete"
  fi
}

run_psk_pki_dual_mode () {
  case_name=psk_pki_dual_mode
  dual_case=$case_name
  echo -n "Concurrent PSK and PKI server configuration - "

  if ! generate_pki_files "$dual_case"; then
    fail_case "$dual_case" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$dual_case" "" "" "" no "" no yes; then
    fail_case "$dual_case" "server did not start"
    return
  fi

  run_client "${dual_case}_psk" "$PSK_KEY" "" "$CLIENT_TIMEOUT"
  run_pki_client "${dual_case}_pki" "$LOGDIR/pki/ca.pem" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/${dual_case}_psk.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/${dual_case}_psk.client" "2\\.05" &&
     assert_contains "$LOGDIR/${dual_case}_pki.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/${dual_case}_pki.client" "2\\.05" &&
     assert_contains "$LOGDIR/${dual_case}_pki.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$dual_case.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$dual_case" "concurrent PSK and PKI server did not complete both handshakes"
  fi
}

run_pki_root_ca_file () {
  case_name=pki_root_ca_file
  echo -n "PKI root CA file mutual authentication - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "" "" "" yes "$pki_dir/ca.pem"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" "$CLIENT_TIMEOUT" yes "$pki_dir/ca.pem"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "CN 'libcoap-test-client' presented by client"; then
    pass_case
  else
    fail_case "$case_name" "PKI root CA file mutual authentication did not complete"
  fi
}

run_pki_root_ca_dir () {
  case_name=pki_root_ca_dir
  echo -n "PKI root CA directory mutual authentication - "
  pki_dir=$LOGDIR/pki
  ca_dir=$pki_dir/ca_dir

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! prepare_ca_hash_dir "$case_name"; then
    fail_case "$case_name" "CA hash directory preparation failed"
    return
  fi
  if ! start_pki_server "$case_name" "" "" "" yes "$ca_dir"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" "$CLIENT_TIMEOUT" yes "$ca_dir"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "CN 'libcoap-test-client' presented by client"; then
    pass_case
  else
    fail_case "$case_name" "PKI root CA directory mutual authentication did not complete"
  fi
}

run_pki_root_ca_file_invalid () {
  case_name=pki_root_ca_file_invalid
  echo -n "PKI invalid root CA file negative - "
  pki_dir=$LOGDIR/pki
  invalid_ca_file=$pki_dir/invalid_ca.pem

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  printf '%s\n' "invalid root ca" > "$invalid_ca_file"
  if ! start_pki_server "$case_name"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" 3 no "$invalid_ca_file"

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|COAP_EVENT_DTLS_ERROR|Unable to set up PKI keys"; then
    pass_case
  else
    fail_case "$case_name" "invalid root CA file reached an unexpected connected/application path"
  fi
}

run_pki_root_ca_dir_invalid () {
  case_name=pki_root_ca_dir_invalid
  echo -n "PKI invalid root CA directory negative - "
  pki_dir=$LOGDIR/pki
  invalid_ca_dir=$pki_dir/invalid_ca_dir

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  mkdir -p "$invalid_ca_dir" || {
    fail_case "$case_name" "invalid CA directory preparation failed"
    return
  }
  printf '%s\n' "invalid root ca" > "$invalid_ca_dir/not-a-hash.0"
  if ! start_pki_server "$case_name"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "" 3 no "$invalid_ca_dir"

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|COAP_EVENT_DTLS_ERROR|Unable to set up PKI keys"; then
    pass_case
  else
    fail_case "$case_name" "invalid root CA directory reached an unexpected connected/application path"
  fi
}

run_pki_missing_client_cert () {
  case_name=pki_missing_client_cert
  echo -n "PKI missing client certificate negative - "

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "" "" "" yes; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$LOGDIR/pki/ca.pem" 3

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|COAP_EVENT_DTLS_ERROR"; then
    pass_case
  else
    fail_case "$case_name" "missing client certificate reached an unexpected connected/application path"
  fi
}

run_pki_san_preferred_over_cn () {
  case_name=pki_san_preferred_over_cn
  echo -n "PKI SAN preferred over CN - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/san_server.pem" \
      "$pki_dir/san_server.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/ca.pem" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI SAN did not override mismatching CN"
  fi
}

run_pki_second_san_preferred_over_cn () {
  case_name=pki_second_san_preferred_over_cn
  echo -n "PKI second SAN preferred over CN - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/second_san_server.pem" \
      "$pki_dir/second_san_server.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/ca.pem" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN 'default.invalid|localhost' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI second SAN not chosen"
  fi
}

run_pki_cn_fallback () {
  case_name=pki_cn_fallback
  echo -n "PKI CN fallback without SAN - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/cn_server.pem" \
      "$pki_dir/cn_server.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/ca.pem" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI CN fallback without SAN did not complete"
  fi
}

run_pki_bad_cn_or_san () {
  case_name=pki_bad_cn_or_san
  echo -n "PKI bad returned CN or SAN - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/alt_server.pem" \
      "$pki_dir/alt_server.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/ca.pem" "$CLIENT_TIMEOUT"

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "SNI 'localhost' not returned in certificate" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI CN or SAN not rejected"
  fi
}

run_pki_wildcard () {
  case_name=pki_wildcard
  echo -n "PKI Wildcard Certificate - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/wildcard_server.pem" \
      "$pki_dir/wildcard_server.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/ca.pem" "$CLIENT_TIMEOUT" "" "" $WILDCARD_URI

  if assert_not_contains "/etc/hosts" "127\\.0\\.0\\.1[[:space:]]+server\\.example"; then
    skip_case "/etc/hosts does not contain '127.0.0.1 server.example'. Add it in."
  elif assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '\\*.example' presented by server" &&
     assert_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI Wildcard Certificate not accepted"
  fi
}

run_pki_wildcard_bad () {
  case_name=pki_wildcard_bad
  echo -n "PKI wrong Wildcard Certificate - "
  pki_dir=$LOGDIR/pki

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name" "$pki_dir/wildcard_bad.pem" \
      "$pki_dir/wildcard_bad.key"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/ca.pem" "$CLIENT_TIMEOUT" "" "" $WILDCARD_URI

  if assert_not_contains "/etc/hosts" "127\\.0\\.0\\.1[[:space:]]+server\\.example"; then
    skip_case "/etc/hosts does not contain '127.0.0.1 server.example'. Add it in."
  elif assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "SNI 'server.example' not returned in certificate" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'"; then
    pass_case
  else
    fail_case "$case_name" "PKI bad Wildcard Certificate accepted"
  fi
}


run_pki_sni () {
  case_name=pki_sni
  echo -n "PKI SNI certificate selection - "
  pki_dir=$LOGDIR/pki
  sni_file=$LOGDIR/$case_name.sni

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi

  printf '%s,%s,%s\n' "$SNI_HOST" "$pki_dir/sni_combined.pem" \
    "$pki_dir/ca.pem" > "$sni_file"

  if ! start_pki_server "$case_name" "$pki_dir/alt_server.pem" \
      "$pki_dir/alt_server.key" "$sni_file"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$pki_dir/ca.pem" "$CLIENT_TIMEOUT"

  if assert_contains "$LOGDIR/$case_name.server" "SNI '$SNI_HOST' requested" &&
     assert_contains "$LOGDIR/$case_name.server" "Switching to using cert '.*sni_combined.pem' \\+ ca '.*ca.pem'" &&
     assert_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_contains "$LOGDIR/$case_name.client" "2\\.05" &&
     assert_contains "$LOGDIR/$case_name.client" "CN '$SNI_HOST' presented by server"; then
    pass_case
  else
    fail_case "$case_name" "PKI SNI certificate selection did not complete"
  fi
}

run_wrong_pki_ca () {
  case_name=wrong_pki_ca
  echo -n "Wrong PKI CA negative - "

  if ! generate_pki_files "$case_name"; then
    fail_case "$case_name" "certificate generation failed"
    return
  fi
  if ! start_pki_server "$case_name"; then
    fail_case "$case_name" "server did not start"
    return
  fi

  run_pki_client "$case_name" "$LOGDIR/pki/bad_ca.pem" 3

  if assert_not_contains "$LOGDIR/$case_name.client" "COAP_EVENT_DTLS_CONNECTED" &&
     assert_not_contains "$LOGDIR/$case_name.server" "call handler for pseudo resource '.well-known/core'" &&
     assert_contains "$LOGDIR/$case_name.client" "No response received within the timeout|cannot send CoAP pdu|COAP_EVENT_DTLS_ERROR"; then
    pass_case
  else
    fail_case "$case_name" "wrong CA reached an unexpected connected/application path"
  fi
}

run_psk_success
run_psk_ipv6_success
run_psk_identity_hint_callback
run_psk_identity_callback
run_wrong_psk
run_client_first_flight_loss
run_server_hello_verify_loss
run_server_flight_loss
run_client_flight_loss_timeout
run_server_flight_loss_timeout
run_psk_sni
run_tls_psk_success
run_tls_psk_peer_close
run_tls_pki_success
run_pki_success
run_pki_intermediate_chain
run_pki_chain_depth_limit
run_pki_chain_depth_too_long
run_pki_self_signed_leaf
run_pki_self_signed_common_ca
run_pki_non_self_signed_override
run_pki_server_pem_buf
run_pki_mutual_auth
run_pki_root_ca_file
run_pki_root_ca_dir
run_pki_root_ca_file_invalid
run_pki_root_ca_dir_invalid
run_psk_pki_dual_mode
run_pki_missing_client_cert
run_pki_san_preferred_over_cn
run_pki_second_san_preferred_over_cn
run_pki_cn_fallback
run_pki_bad_cn_or_san
run_pki_wildcard
run_pki_wildcard_bad
run_pki_sni
run_wrong_pki_ca

echo
echo "DTLS/TLS backend tests: $NO_PASS passed, $NO_FAIL failed, $NO_SKIP skipped"

if ! check_sanitizer_logs; then
  NO_FAIL=$((NO_FAIL + 1))
fi

if [ "$NO_FAIL" -ne 0 ]; then
  exit 1
fi

exit 0
