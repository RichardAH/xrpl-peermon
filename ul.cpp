#include <sodium.h>

#include <iostream>
#include <string_view>
#include <string>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h> 

#include <stdio.h>
#include <secp256k1.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <libbase58.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "peers.h"
#include "ripple.pb.h"

#define DEBUG 1

template<class... Args>
int printd(Args ... args)
{
    (std::cerr << ... << args) << "\n";
    return 1;
}

int connect_peer(std::string_view ip_port) {

    auto x = ip_port.find_last_of(":");
    if (x == std::string_view::npos)
        return printd("[DBG] Could not find port in ", ip_port), -1;

    std::string ip { ip_port.substr(0, x) };
    long port = strtol(ip_port.substr(x+1).data(), 0, 10);

    if (port <= 0)
        return printd("[DBG] Port of ", ip_port, " parsed to 0 or neg"), -1;    

    int sockfd = 0;
    struct sockaddr_in serv_addr; 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return printd("[DBG] Could not create socket for ", ip_port, "\n"), -1;

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); 

    if(inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr)<=0)
        return printd("[DBG] Could not create socket for ", ip_port," inet_pton error occured"), -1;

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        return printd("[DBG] Could not connect to ", ip_port), -1;

    return sockfd;
}


int generate_node_keys(unsigned char* outsec32, unsigned char* outpubraw64, unsigned char* outpubcompressed33, char* outnodekeyb58, size_t* outnodekeyb58size) {
    
    // create secp256k1 context and randomize it

    int rndfd = open("/dev/urandom", O_RDONLY);

    if (rndfd < 0) {
        fprintf(stderr, "[FATAL] Could not open /dev/urandom for reading\n");
        exit(1);
    }

    secp256k1_context* ctx = secp256k1_context_create(
                SECP256K1_CONTEXT_VERIFY |
                SECP256K1_CONTEXT_SIGN) ;


    unsigned char seed[32];
    auto result = read(rndfd, seed, 32);
    if (result != 32) {
        fprintf(stderr, "[FATAL] Could not read 32 bytes from /dev/urandom\n");
        exit(2);
    }

    if (!secp256k1_context_randomize(ctx, seed)) {
        fprintf(stderr, "[FATAL] Could not randomize secp256k1 context\n");
        exit(3);
    }


    result = read(rndfd, outsec32, 32);
    if (result != 32) {
        fprintf(stderr, "[FATAL] Could not read 32 bytes from /dev/urandom\n");
        exit(4);
    }

    secp256k1_pubkey* pubkey = (secp256k1_pubkey*)((void*)(outpubraw64));

    if (!secp256k1_ec_pubkey_create(ctx, pubkey, (const unsigned char*)outsec32)) {
        fprintf(stderr, "[FATAL] Could not generate secp256k1 keypair\n");
        exit(5);
    }

    size_t out_size = 33;
    secp256k1_ec_pubkey_serialize(ctx, outpubcompressed33, &out_size, pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char outpubcompressed38[38];

    // copy into the 38 byte check version
    for(int i = 0; i < 33; ++i) outpubcompressed38[i+1] = outpubcompressed33[i];

    // clean up
    close(rndfd);
    secp256k1_context_destroy(ctx);

    // pub key must start with magic type 0x1C
    outpubcompressed38[0] = 0x1C;
    // generate the double sha256
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, outpubcompressed38, 34);

    unsigned char hash2[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash2, hash, crypto_hash_sha256_BYTES);

    // copy checksum bytes to the end of the compressed key
    for (int i = 0; i < 4; ++i) 
        outpubcompressed38[34+i] = hash2[i];


    // generate base58 encoding
    b58enc(outnodekeyb58, outnodekeyb58size, outpubcompressed38, 38);

    outnodekeyb58[*outnodekeyb58size] = '\0';

}

int main() {


    if (sodium_init() < 0) {
        fprintf(stderr, "[FATAL] Could not init libsodium\n");
        exit(6);
    }

    SSL_library_init();


    // generate keys


    unsigned char sec[32], pub[64], pubc[33];
    char b58[100];
    size_t b58size = 100;
    generate_node_keys(sec, pub, pubc, b58, &b58size);
    printf("size: %lu\n", b58size);

    printf("seckey: ");
    for (int i = 0; i < 32; ++i)
        printf("%02X", sec[i]);
    printf("\npubkey: ");
    for (int i = 0; i < 33; ++i)
        printf("%02X", pub[i]);
    printf("\n");
    printf("base58: %s\n", b58); 


/*
    int fd = -1;

    for (auto& v: peers) {
        std::cout << v << "\n";
        std::cout << "socketfd: " << (fd = connect_peer(v)) << "\n";
        break;
    }
*/

    


    return 0;
}
