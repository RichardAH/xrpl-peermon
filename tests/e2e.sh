#!/bin/bash
# End-to-end tests: peermon against tests/mock_peer, which enforces xahaud's
# handshake rules (session signature, Network-ID absent == 0, version
# negotiation). Run from the repo root after `make peermon tests/mock_peer`.
set -u
cd "$(dirname "$0")/.."
[ -f tests/peer.cert ] || openssl req -nodes -new -x509 -subj /CN=peermon-test \
    -keyout tests/peer.key -out tests/peer.cert -days 2 2>/dev/null
LISTEN_DIR=$(mktemp -d); cp tests/peer.cert "$LISTEN_DIR/listen.cert"; cp tests/peer.key "$LISTEN_DIR/listen.key"
PEERMON=$(pwd)/peermon
PORT=$(( 30000 + RANDOM % 20000 ))
FAILS=0
vec() { python3 -c "import json,sys;v=json.load(open('tests/vectors_$1.json'));print(' '.join(('v:' if 'Validation' in x['name'] else 't:')+x['hex'] for x in v))"; }
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; FAILS=$((FAILS+1)); fi; }
serve() { PORT=$((PORT+1)); (timeout 20 ./tests/mock_peer serve $PORT "$@" > /tmp/peermon_e2e_mock.log 2>&1 &); sleep 0.5; }

serve 21337 2.1,2.2
timeout 10 $PEERMON 127.0.0.1 $PORT no-http no-stats > /dev/null 2> /tmp/peermon_e2e.err; rc=$?
check "Xahau peer, no network option: refused with a clear hint" \
    "[ $rc = 2 ] && grep -q 'Add .xahau.' /tmp/peermon_e2e.err"

serve 21337 2.1,2.2 $(vec xahau)
timeout 15 $PEERMON 127.0.0.1 $PORT xahau no-stats no-cls no-hex no-http > /tmp/peermon_e2e.out 2>/dev/null
check "xahau: handshake verified by xahaud rules, Network-ID 21337" \
    "grep -q 'session signature verified, peer Network-ID 21337' /tmp/peermon_e2e_mock.log"
check "xahau: coalesced batch fully decoded, no unknown fields" \
    "[ \$(grep -c 'mtTRANSACTION' /tmp/peermon_e2e.out) = 14 ] && grep -q '\"TransactionType\": \"SetHook\"' /tmp/peermon_e2e.out && ! grep -q 'UnknownField\|Error' /tmp/peermon_e2e.out"
check "xahau: pings answered" "grep -q 'got both PONGs' /tmp/peermon_e2e_mock.log"

serve none 2.2,2.3 $(vec xrpl)
timeout 15 $PEERMON 127.0.0.1 $PORT no-stats no-cls no-hex no-http > /tmp/peermon_e2e.out 2>/dev/null
check "XRPL peer offering only 2.2/2.3 (rippled develop): negotiates 2.2" \
    "grep -q 'Network-ID (absent), negotiated XRPL/2.2' /tmp/peermon_e2e_mock.log && grep -q 'got both PONGs' /tmp/peermon_e2e_mock.log"
check "XRPL: decoded with XRPL definitions" \
    "[ \$(grep -c 'mtTRANSACTION' /tmp/peermon_e2e.out) = 7 ] && grep -q '\"TransactionType\": \"VaultCreate\"' /tmp/peermon_e2e.out && ! grep -q 'UnknownField\|Error' /tmp/peermon_e2e.out"

serve 21338 2.1,2.2 $(vec xahau)
timeout 15 $PEERMON 127.0.0.1 $PORT network-id:21338 no-cls no-dump no-http > /tmp/peermon_e2e.out 2>/dev/null
check "network-id:21338 selects Xahau definitions" "grep -q 'Xahau, Network-ID 21338' /tmp/peermon_e2e.out"

PORT=$((PORT+1))
(cd "$LISTEN_DIR" && timeout 15 $PEERMON 127.0.0.1 $PORT listen no-cls no-stats no-http > /dev/null 2>&1 &)
sleep 0.7
timeout 10 ./tests/mock_peer connect $PORT 21337 > /tmp/peermon_e2e_mock.log 2>&1
check "listen mode: adopts xahaud's Network-ID, response verified, well formed ping" \
    "grep -q 'Network-ID 21337' /tmp/peermon_e2e_mock.log && grep -q 'well formed 2 byte TMPing' /tmp/peermon_e2e_mock.log"

rm -rf "$LISTEN_DIR"
[ $FAILS = 0 ] && echo "E2E PASSED" || echo "E2E: $FAILS FAILED"
exit $FAILS
