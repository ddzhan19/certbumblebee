#!/bin/bash
# Startet Pebble (ACME-Testserver) und challtestsrv (Test-DNS). Die Programme müssen in ../bin liegen:
#   GOBIN=$PWD/bin go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
#   GOBIN=$PWD/bin go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
# Das Testzertifikat für Pebble (pebble.crt/pebble.key) wird beim ersten Start erzeugt. PIDs landen in *.pid.
cd "$(dirname "$0")"
BIN=../bin
if [ ! -f pebble.crt ] || [ ! -f pebble.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -keyout pebble.key -out pebble.crt -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
fi
export PEBBLE_VA_NOSLEEP=1
nohup $BIN/pebble-challtestsrv -http01 "" -https01 "" -tlsalpn01 "" -doh "" -dnsserver "127.0.0.1:8053" -management "127.0.0.1:8055" -defaultIPv4 127.0.0.1 -defaultIPv6 "" > challtest.log 2>&1 &
echo $! > challtest.pid
sleep 0.5
nohup $BIN/pebble -config pebble-config.json -dnsserver 127.0.0.1:8053 > pebble.log 2>&1 &
echo $! > pebble.pid
sleep 1.5
curl -s --noproxy '*' --cacert pebble.crt -o /dev/null -w "pebble directory: %{http_code}\n" https://localhost:14000/dir
