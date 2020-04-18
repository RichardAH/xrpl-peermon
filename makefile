all:
	 g++ ul.cpp --std=c++17 -lsecp256k1 -lsodium -lbase58 -lssl -lcrypto
