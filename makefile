peermon: peermon.cpp ripple.pb.cc base58.c libbase58.h sha-256.c xd.h xd.c 
	clang++ peermon.cpp ripple.pb.cc base58.c xd.c sha-256.c --std=c++17 -lsecp256k1 -lsodium -lssl -lcrypto -lprotobuf --std=c++20  -g -o peermon
ripple.pb.cc:
	protoc --cpp_out=. ripple.proto
	
