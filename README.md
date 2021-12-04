# XRPL Peer Monitor

A commandline utility to monitor the traffic being emitted by an XRPL peer in realtime.

# Building
Assuming you are on Ubuntu 20+:
```
git clone https://github.com/RichardAH/xrpl-peermon.git
cd xrpl-peermon
apt install libsodium-dev libsecp256k1-dev libprotobuf-dev protobuf-compiler libssl-dev -y
make
```

# Usage
Usage:

```
XRPL Peer Monitor
Version: 1.31
Richard Holland / XRPL-Labs
A tool to connect to a rippled node as a peer and monitor the traffic it produces
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
Show / Hide:
        show:mtPACKET[,mtPACKET...]             - Show only the packets in the comma seperated list (no spaces!)
        hide:mtPACKET[,mtPACKET...]             - Show all packets except those in the comma seperated list.
Packet Types:
        mtMANIFESTS mtPING mtCLUSTER mtENDPOINTS mtTRANSACTION mtGET_LEDGER mtLEDGER_DATA mtPROPOSE_LEDGER
        mtSTATUS_CHANGE mtHAVE_SET mtVALIDATION mtGET_OBJECTS mtGET_SHARD_INFO mtSHARD_INFO mtGET_PEER_SHARD_INFO
        mtPEER_SHARD_INFO mtVALIDATORLIST mtSQUELCH mtVALIDATORLISTCOLLECTION mtPROOF_PATH_REQ mtPROOF_PATH_RESPONSE
        mtREPLAY_DELTA_REQ mtREPLAY_DELTA_RESPONSE mtGET_PEER_SHARD_INFO_V2 mtPEER_SHARD_INFO_V2 mtHAVE_TRANSACTIONS
        mtTRANSACTIONS
Keys:
        When connecting, peermon choses a random secp256k1 node key for itself.
        If this is not the behaviour you want please place a binary 32 byte key file at ~/.peermon.
```

Example:
```
        ./peermon zaphod.alloy.ee 51235 no-dump                                    # display realtime stats for this node
        ./peermon zaphod.alloy.ee 51235 no-cls no-stats show:mtGET_LEDGER          # show only the GET_LEDGER packets
```

# Output
```
XRPL-Peermon -- Connected to Peer: --:51235 for 7 sec

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
