# XRPL Peer Monitor

A commandline utility to monitor the traffic being emitted by an XRPL or Xahau peer in realtime.

# Building
Assuming you are on Ubuntu 20+:
```
git clone https://github.com/RichardAH/xrpl-peermon.git
cd xrpl-peermon
apt install clang pkg-config libsodium-dev libsecp256k1-dev libprotobuf-dev protobuf-compiler libssl-dev -y
make
```
`make info` shows which compiler, `protoc` and protobuf the build resolved. Use `make CXX=g++` for gcc.

Protobuf is resolved with pkg-config, so the generated code, headers and libraries (including abseil
for protobuf 22+) all come from the same install, and `protoc` defaults to the one in that install.
A protobuf built into `/usr/local` next to the distro's `libprotobuf-dev` otherwise links against the
wrong library (undefined `google::protobuf::internal::...` references), because the linker searches
`/usr/lib/<arch>` before `/usr/local/lib` while `PATH` and the include path prefer `/usr/local`.
To pick a specific install: `PKG_CONFIG_PATH=/opt/protobuf/lib/pkgconfig make`. `ripple.pb.*` is
regenerated automatically when `ripple.proto`, the compiler, `protoc` or the protobuf install changes.

Clang 18+ mangles some templates differently from GCC, so linking against an abseil built by GCC
(the usual case for protobuf 22+) fails with undefined `absl::...LogMessage::operator<<` references.
The build probes for this once per toolchain and adds `-fclang-abi-compat=17` only when needed.

# Usage
Usage:

```
XRPL / Xahau Peer Monitor
Version: 1.40
Richard Holland / XRPL-Labs
A tool to connect to a rippled or xahaud node as a peer and monitor the traffic it produces
Usage: ./peermon IP PORT [OPTIONS] [show:mtPACKET,... | hide:mtPACKET,...]
Options:
        slow            - Only print at most once every 5 seconds. Will skip displaying most packets. Use for stats.
        no-cls          - Don't clear the screen between printing. If you're after packet contents use this.
        no-dump         - Don't dump any packet contents.
        no-stats        - Don't produce stats.
        no-http         - Don't output HTTP upgrade.
        manifests-only  - Only collect and print manifests then exit.
        raw-hex         - Print raw hex where appropriate instead of giving it line numbers and spacing.
        no-hex          - Never print hex, only parsed / able-to-be-parsed STObjects or omit.
        listen          - experimental do not use.
Network:
        xahau           - Xahau: decode with Xahau definitions and send Network-ID 21337 (Xahau mainnet)
                          unless network-id:N is also given.
        network-id:N    - Send Network-ID N in the handshake. Needed for every Xahau network and for
                          non-mainnet XRPL networks. IDs 21330-21339 (Xahau) imply `xahau`.
                          Default: no Network-ID header and XRPL definitions.
Show / Hide:
        show:mtPACKET[,mtPACKET...]             - Show only the packets in the comma seperated list (no spaces!)
        hide:mtPACKET[,mtPACKET...]             - Show all packets except those in the comma seperated list.
Packet Types:
        mtMANIFESTS mtPING mtCLUSTER mtENDPOINTS mtTRANSACTION mtGET_LEDGER mtLEDGER_DATA mtPROPOSE_LEDGER
        mtSTATUS_CHANGE mtHAVE_SET mtVALIDATION mtGET_OBJECTS mtGET_SHARD_INFO mtSHARD_INFO mtGET_PEER_SHARD_INFO
        mtPEER_SHARD_INFO mtVALIDATORLIST mtSQUELCH mtVALIDATORLISTCOLLECTION mtPROOF_PATH_REQ mtPROOF_PATH_RESPONSE
        mtREPLAY_DELTA_REQ mtREPLAY_DELTA_RESPONSE mtGET_PEER_SHARD_INFO_V2 mtPEER_SHARD_INFO_V2 mtHAVE_TRANSACTIONS
        mtTRANSACTIONS  mtRESOURCE_REPORT
Keys:
        When connecting, peermon choses a random secp256k1 node key for itself.
        If this is not the behaviour you want please place a binary 32 byte key file at ~/.peermon.
```

Example:
```
        ./peermon zaphod.alloy.ee 51235 no-dump                                    # display realtime stats for this node
        ./peermon zaphod.alloy.ee 51235 no-cls no-stats show:mtGET_LEDGER          # show only the GET_LEDGER packets
        ./peermon hubs.xahau.as16089.net 21337 xahau no-dump                       # Xahau mainnet stats
        ./peermon bacab.alloy.ee 21337 xahau no-cls no-stats show:mtTRANSACTION    # decoded Xahau transactions
```

# Xahau
xahaud treats a missing `Network-ID` handshake header as network 0 and refuses the connection with
`400 Bad Request (Peer is on a different network)`. Pass `xahau` (mainnet, 21337) or `network-id:N`
(e.g. `network-id:21338` for testnet). rippled only checks the header when it is present, so XRPL
mainnet needs neither option.

XRPL and Xahau share the binary format but not the field / transaction / ledger entry tables (several
codes mean different things on each network), so transactions and validations are decoded with the
selected network's tables. Those live in `xd_defs.h`, generated from each server's own definition
macros; to refresh them after new amendments:
```
make defs XRPL_SRC=../rippled XAHAU_SRC=../xahaud
```

# Tests
```
make test   # decoder: codec-generated XRPL and Xahau vectors (needs python3)
make e2e    # peermon against a mock peer enforcing xahaud's handshake rules (needs openssl)
```
The vectors in `tests/vectors_*.json` are produced by the official `ripple-binary-codec` and
`xahau-binary-codec`; regenerate with `npm install ripple-binary-codec xahau-binary-codec && node tests/gen_vectors.js`.

# Output
```
XRPL-Peermon -- Connected to Peer: --:51235 [XRPL, rippled-2.2.2] for 7 sec

Packet                    Total               Per second          Total Bytes         Data rate
------------------------------------------------------------------------------------------------------
mtMANIFESTS               1                   0.142857            195.07 K            27.87 K/s
mtTRANSACTION             166                 23.7143             35.39 K             5.06 K/s
mtPROPOSE_LEDGER          104                 14.8571             18.63 K             2.66 K/s
mtSTATUS_CHANGE           3                   0.428571            273.00 B            39.00 B/s
mtHAVE_SET                57                  8.14286             2.00 K              293.14 B/s
mtVALIDATION              245                 35                  55.25 K             7.89 K/s
mtGET_PEER_SHARD_INFO_V2  1                   0.142857            2.00 B              0.29 B/s
------------------------------------------------------------------------------------------------------
Totals                    577                 82.4286             306.61 K            43.80 K/s


Latest packet: mtVALIDATION [41] -- 236 bytes
```
