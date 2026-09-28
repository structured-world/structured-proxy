#!/bin/sh
# Test PKI for src/tls/tests.rs: a CA, an ECDSA and an RSA leaf for
# `localhost`, and an unrelated CA; for mTLS, a client CA and a client leaf
# (tests/serve.rs). Valid for 100 years.
set -eu
out="$1"
cd "$out"
days=36500

ext_leaf="basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost"

ca() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.key.tmp"
  openssl pkcs8 -topk8 -nocrypt -in "$1.key.tmp" -out "$1.key.pem"
  rm "$1.key.tmp"
  openssl req -x509 -new -key "$1.key.pem" -days "$days" -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$1.pem"
}

leaf() {
  name="$1"
  printf '%s\n' "$ext_leaf" > "$name.ext"
  openssl req -new -key "$name.key.pem" -subj "/CN=localhost" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key.pem -CAcreateserial \
    -days "$days" -extfile "$name.ext" -out "$name.pem"
  rm "$name.csr" "$name.ext"
}

ca ca "structured-proxy test CA"
ca other-ca "unrelated test CA"
rm other-ca.key.pem

openssl ecparam -name prime256v1 -genkey -noout -out ecdsa.key.tmp
openssl pkcs8 -topk8 -nocrypt -in ecdsa.key.tmp -out ecdsa.key.pem
rm ecdsa.key.tmp
leaf ecdsa

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key.pem
leaf rsa

# A client certificate, which a verifier of client certificates accepts only
# with the clientAuth extended key usage (RFC 5280 4.2.1.12).
ca client-ca "structured-proxy test client CA"
openssl ecparam -name prime256v1 -genkey -noout -out client.key.tmp
openssl pkcs8 -topk8 -nocrypt -in client.key.tmp -out client.key.pem
rm client.key.tmp
printf '%s\n' "basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth" > client.ext
openssl req -new -key client.key.pem -subj "/CN=test client" -out client.csr
openssl x509 -req -in client.csr -CA client-ca.pem -CAkey client-ca.key.pem -CAcreateserial \
  -days "$days" -extfile client.ext -out client.pem
rm client.csr client.ext

rm -f ca.srl ca.key.pem client-ca.srl client-ca.key.pem
