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
./peermon PEER-IP PORT [OPTIONS]
Options:
        no-cls          - Don't clear the screen between printing stats.
        no-dump         - Don't dump the latest packet contents.
        slow            - Only print at most once every 5 seconds.
        manifests-only  - Only collect and print manifests then exit.
        raw             - Print raw hex where appropriate instead of giving it line numbers and spacing.
```

Example:

```
./peermon r.ripple.com 51235
```

# Output
```
XRPL-Peermon
Connected to Peer: 34.205.233.231:51235 for 6 sec

Packet                    Total               Per second          Total Bytes         Data rate       
------------------------------------------------------------------------------------------------------
mtMANIFESTS               2                   0.333333            186.29 K            31.05 K/s
mtTRANSACTION             112                 18.6667             25.14 K             4.19 K/s
mtPROPOSE_LEDGER          90                  15                  16.13 K             2.69 K/s
mtSTATUS_CHANGE           4                   0.666667            364.00 B            60.67 B/s
mtHAVE_SET                22                  3.66667             792.00 B            132.00 B/s
mtVALIDATION              285                 47.5                64.25 K             10.71 K/s
mtGET_PEER_SHARD_INFO     1                   0.166667            2.00 B              0.33 B/s
------------------------------------------------------------------------------------------------------
Totals                    516                 86                  292.96 K            48.83 K/s


Latest packet: mtVALIDATION [41] -- 236 bytes
parsed validation: yes
stvalidation data: 2280000001260404FAE8292913E3C83A9DFC8E9E5ABBFB9A51FB214934575298D71081553C61331A2406F7931D21B1588263CE641D8C1B16C250176967A69444C1ACBD7DF1EBE115C17A61CB01CB4A7FBD3E3F21EE33EE02653E395019F5CC91CF06D8431B8627A2C3B82F11AD17DD8246F5774140186901E02DED6B037321038D4BA061B8E1DF5366A4F46DA92BF5DA450AA2FE7E05C220D9806027977F869C76473045022100F95C0B19112AE6BB169E9409791A87D4BECBBAEFF964A25D8007CF71EDF599B2022049A3716D3F90BC322DB4BCCF29540FD04F3EB88AC37A77B66EAC75B963337AC9
{
	"Flags": 2147483649,
	"LedgerSequence": 67435240,
	"SigningTime": 689169352,
	"Cookie": 113841307688640,
	"LedgerHash": "FB214934575298D71081553C61331A2406F7931D21B1588263CE641D8C1B16C2",
	"ConsensusHash": "6967A69444C1ACBD7DF1EBE115C17A61CB01CB4A7FBD3E3F21EE33EE02653E39",
	"ValidatedHash": "F5CC91CF06D8431B8627A2C3B82F11AD17DD8246F5774140186901E02DED6B03",
	"SigningPubKey": "038D4BA061B8E1DF5366A4F46DA92BF5DA450AA2FE7E05C220D9806027977F869C",
	"Signature": 
}
```
