#!/bin/bash

base=${0##*/}
params="${base}-params"
pem="${base}-params"
pfx=${1:-server.pfx}

cleanup() {
  rm -f $params $pem
}
  
trap cleanup ERR EXIT

cat >$params <<END_PARAMS
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
END_PARAMS

openssl req -x509 -nodes -days 365 -newkey ec:$params -subj '/CN=test' -sha256 -keyout $pem -out $pem
openssl pkcs12 -export -nodes -password pass: -in $pem -name server -out $pfx
