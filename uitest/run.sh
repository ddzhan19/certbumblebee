#!/bin/bash
# Startet die Linux-Fassung für Browser-Tests. Aufruf: uitest/run.sh <Lauf-Name>
# Die Daten des Laufs liegen in uitest/<Lauf-Name>/. Voraussetzung: bin/certbumblebee-linux und pebble/pebble.crt (pebble/up.sh).
S="$(cd "$(dirname "$0")/.." && pwd)"
R="$S/uitest/$1"
mkdir -p "$R/data" "$R/target" "$R/web"
export ZA_DATA="$R/data" ZA_NO_BROWSER=1 ZA_PORT=8765 ZA_HTTP_PORT=5002 SSL_CERT_FILE="$S/pebble/pebble.crt"
cd "$R"
nohup "$S/bin/certbumblebee-linux" ui --no-browser --port 8765 > server.log 2>&1 &
echo $! > "$S/uitest/server.pid"
sleep 1
