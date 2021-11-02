peermon: peermon.cpp ripple.pb.cc base58.c libbase58.h sha-256.c xd.h xd.c 
	 g++ peermon.cpp ripple.pb.cc base58.c xd.c sha-256.c --std=c++17 -lsecp256k1 -lsodium -lssl -lcrypto -lprotobuf -fpermissive -Bstatic  -g -o peermon
	
