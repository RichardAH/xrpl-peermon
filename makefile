all:
	 g++ ul.cpp ripple.pb.cc base58.c --std=c++17 -lsecp256k1 -lsodium -lssl -lcrypto -lprotobuf
