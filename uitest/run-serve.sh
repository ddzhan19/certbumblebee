#!/bin/bash
# Startet den Dauerbetrieb („serve“) für Browser-Tests. Aufruf: uitest/run-serve.sh <Lauf-Name>
# Voraussetzung: bin/certbumblebee-linux, Pebble (pebble/up.sh) und uitest/fakecf.py auf Port 18787.
S="$(cd "$(dirname "$0")/.." && pwd)"
R="$S/uitest/$1"
mkdir -p "$R/data" "$R/target"
export ZA_DATA="$R/data" ZA_LISTEN=127.0.0.1:8766 ZA_PASSWORD="Test-Passwort-12345" ZA_SECRET_KEY="uitest-schluessel-0123456789abcdef" \
  ZA_CLOUDFLARE_API=http://127.0.0.1:18787 SSL_CERT_FILE="$S/pebble/pebble.crt" TZ=Europe/Berlin
cd "$R"
nohup "$S/bin/certbumblebee-linux" serve > server.log 2>&1 &
echo $! > "$S/uitest/serve.pid"
