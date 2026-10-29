#!/bin/bash
cd "$(dirname "$0")"
for f in pebble.pid challtest.pid; do [ -f $f ] && kill "$(cat $f)" 2>/dev/null; rm -f $f; done
echo gestoppt
